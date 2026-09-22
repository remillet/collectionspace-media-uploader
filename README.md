# CollectionSpace Media Uploader

A small Flask web app that logs in to a CollectionSpace instance, then
creates a CollectionSpace **Media** record and links an uploaded
photo/document to it as a **Blob** record.

Once logged in, it performs the two-call sequence documented in the
CollectionSpace Technical Documentation ([Media Service REST APIs](https://collectionspace.atlassian.net/wiki/spaces/cstd/pages/3581444097/Media+Service+REST+APIs)),
verified against the [collectionspace/services](https://github.com/collectionspace/services)
source code:

1. `POST /media` &mdash; creates the Media record from the Title and ID you provide.
2. `PUT /media/{csid}/blob` &mdash; uploads your file, which creates a Blob record
   and links it to the Media record created in step 1.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### AWS setup (required)

CollectionSpace credentials you enter are stored in **AWS Secrets Manager**
for the life of your login, not in the Flask session cookie or on disk.
The app needs AWS credentials available the way boto3 normally looks for
them (environment variables, `~/.aws/credentials`, an instance/task role,
etc.), scoped to at least these actions on the
`collectionspace-uploader/session/*` secret name prefix:

- `secretsmanager:CreateSecret`
- `secretsmanager:GetSecretValue`
- `secretsmanager:DeleteSecret`

**Recommended: a dedicated named profile.** Rather than using your default
AWS CLI credentials for this app, create a profile just for it so its
access stays separate from anything else you use boto3/the AWS CLI for:

```bash
aws configure --profile collectionspace-uploader
```

This prompts for an Access Key ID, Secret Access Key, default region, and
output format, and writes them to `~/.aws/credentials` and
`~/.aws/config` under that profile name -- nothing to add to this repo or
its `.gitignore`. Then run the app with that profile active:

```bash
AWS_PROFILE=collectionspace-uploader python app.py
```

You can sanity-check the profile resolves correctly (without exposing the
secret key itself) with:

```bash
aws sts get-caller-identity --profile collectionspace-uploader
```

Optional environment variables:

- `AWS_PROFILE` &mdash; which `~/.aws` profile to use, per above. Falls back to
  the default profile (or instance/task role credentials) if unset.
- `AWS_REGION` &mdash; which region to create secrets in (falls back to boto3's
  normal region resolution -- including the profile's configured region --
  if unset here).
- `FLASK_SECRET_KEY` &mdash; a stable key for signing the Flask session cookie.
  Without it, a random key is generated on each restart, which logs
  everyone out whenever the app restarts. Set this to anything long and
  random for a login that survives restarts.
- `FLASK_SESSION_COOKIE_SECURE=1` &mdash; set this once the app is served over
  HTTPS, so the session cookie is only ever sent over an encrypted
  connection. Leave it unset for local HTTP development.

## Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Logging in

The CollectionSpace REST API has no session or login endpoint of its own
&mdash; every call authenticates independently via HTTP Basic Auth. This app
adds a login on top of that:

1. On first visit, you're sent to **/login** and asked for your
   CollectionSpace instance URL, username, and password.
2. The app verifies those credentials with a lightweight authenticated
   call to the instance (`GET /accounts/0/accountperms`), rather than
   waiting until you try to create a record to find out they're wrong.
   `0` is a real sentinel in the CollectionSpace services source
   (`JpaStorageUtils.CS_CURRENT_USER`) meaning "whichever account is
   currently authenticated" -- so this works for any valid account, not
   just admins who can list all accounts.
3. That same call's response also tells the app what the account is
   *allowed to do*. The app parses it for `resourceName` = `media`
   entries and checks that the combined `actionGroup` across all of
   them includes both `C` (create, needed for `POST /media`) and `U`
   (update, needed for `PUT /media/{csid}/blob`) -- an account's media
   permissions can come from more than one role, so entries are unioned
   rather than requiring one to have both. If either is missing, login
   is rejected with a message naming what's missing, instead of letting
   you discover it mid-upload as a raw 403. This adds no extra API call
   &mdash; it's the same `/accounts/0/accountperms` request from step 2.
   (Only `media` permissions matter here -- see
   [Checking an account's permissions](#checking-an-accounts-permissions)
   below for why the separate Blob service's permissions are beside the
   point.)
4. On success, your credentials are stored in AWS Secrets Manager and a
   reference to that secret is kept in your (signed, HTTP-only) Flask
   session cookie &mdash; the password itself never touches the cookie.
5. Every subsequent CollectionSpace API call fetches the credentials
   fresh from Secrets Manager for that one call.
6. **Log out** (link in the top nav) deletes the secret and clears your
   session.

**Known limitation:** if you close the browser without clicking "Log
out," the Secrets Manager secret for that login isn't automatically
deleted &mdash; Flask's cookie-based sessions don't have a server-side expiry
hook to trigger cleanup. For anything beyond local/personal use, pair
this app with a scheduled job that deletes secrets under the
`collectionspace-uploader/session/` prefix past some age (each secret's
description includes its creation time).

## Checking an account's permissions

If login is rejected for missing Media permissions, or you just want to
confirm what an account can do before handing it to someone, run the
included diagnostic script:

```bash
python3 check_media_permissions.py
```

It prompts for the instance URL, username, and password (the password
is entered via `getpass` -- never echoed, logged, or written anywhere)
and prints every `resourceName`/`actionGroup` entry from that account's
`GET /accounts/0/accountperms` response that mentions "media" or
"blob," e.g.:

```
  resourceName='media'  actionGroup='CRUL'
```

**Only the `media` resource's permissions matter for this app.**
CollectionSpace also has a separate, standalone **Blob** service with
its own line in the permissions admin UI, but this app is never
authorized against it. `PUT /media/{csid}/blob` is a *sub-resource* of
Media, and CollectionSpace's `SecurityInterceptor` collapses
sub-resource paths like `{csid}/blob` to their parent resource
(`media`) for authorization purposes before the request is checked at
all. The Media resource's own request handler then creates the Blob
record on your behalf via an internal, in-process call that never
re-enters that authorization check. Practically, that means:

- An account can have **no** permissions on the Blob service and still
  successfully create Blob records through this app, as long as it has
  `U` on `media`.
- Granting an account permissions on the Blob service alone won't help
  it if the account lacks `C`/`U` on `media` -- that's not the
  permission this app's calls are ever checked against.

This is what step 3 above and `verify_media_permissions()` in `app.py`
check for; `check_media_permissions.py` is the same query with the raw
result printed instead of turned into a pass/fail decision, useful for
seeing exactly what an account has when something doesn't match your
expectations.

## Using the form

- **CollectionSpace instance URL** &mdash; the base URL of your instance, e.g.
  `https://myinstance.collectionspace.org`. `/cspace-services` is appended
  automatically if you leave it off.
- **Username / password** &mdash; your CollectionSpace account credentials,
  checked once at login and then stored in AWS Secrets Manager for the
  rest of your session.
- **Verify SSL certificate** &mdash; leave checked unless you're pointing at a
  self-hosted/sandbox instance with a self-signed certificate you trust.
- **Title** / **ID** &mdash; used to populate the new Media record's `title` and
  `identificationNumber` fields.
- **Photo or document to upload** &mdash; the file that becomes the linked Blob
  record's content.

On success, the result page shows the new Media record's CSID and direct
links to the Media record, the Blob record, and the raw file content.

## Security notes

- Your CollectionSpace password is used only to verify your login and to
  populate a short-lived AWS Secrets Manager secret; it's fetched fresh
  from Secrets Manager for each API call rather than cached in memory.
  It is never logged or written to local disk.
- The Flask session cookie is signed, HTTP-only, and holds only a secret
  reference plus your username and instance URL &mdash; never your password.
- Nothing about a given upload is persisted server-side beyond your login
  &mdash; each `/create` submission is a fresh, in-memory round trip.
- Only run this against a CollectionSpace instance and account you
  control and trust. This app is intended for local/personal use; it
  is not hardened for exposure on a public network (no rate limiting,
  no CSRF protection beyond Flask's defaults, debug mode is on by
  default in `app.py`).
