# CollectionSpace Media Uploader

A small Flask web app that logs in to a CollectionSpace instance, then
creates a CollectionSpace **Media** record and links an uploaded
photo/document to it as a **Blob** record.

Once logged in, it performs this sequence, documented in the
CollectionSpace Technical Documentation ([Media Service REST APIs](https://collectionspace.atlassian.net/wiki/spaces/cstd/pages/3581444097/Media+Service+REST+APIs)),
verified against the [collectionspace/services](https://github.com/collectionspace/services)
source code:

1. `POST /media` &mdash; creates the Media record from the Title and ID you
   provide, and, if you chose one, a **Contributor** &mdash; a term drawn from
   a fixed set of CollectionSpace Person and/or Organization Authority
   instances. See [The Contributor field](#the-contributor-field) below.
2. `PUT /media/{csid}/blob` &mdash; uploads your file, which creates a Blob record
   and links it to the Media record created in step 1.
3. *Optional:* `POST /relations` &mdash; if you asked to relate the Media record
   to an existing Object record, links the two. See
   [Relating a Media record to an Object record](#relating-a-media-record-to-an-object-record)
   below.

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
- `CONTRIBUTOR_AUTHORITIES_CONFIG_PATH` &mdash; overrides where the app looks
  for the **Contributor** field's YAML config file. Defaults to
  `contributor_authorities.yaml` next to `app.py`, which is checked into
  the repo, so most setups don't need to set this at all. See
  [The Contributor field](#the-contributor-field) below.

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
- **Contributor** &mdash; optional. A type-ahead field: start typing a name and
  pick a matching suggestion from Person and/or Organization Authority terms
  drawn from a fixed, admin-configured set of instances &mdash; not free text.
  See [The Contributor field](#the-contributor-field) below.
- **Relate this Media record to an existing Object record** / **Object
  Number** &mdash; optional. See
  [Relating a Media record to an Object record](#relating-a-media-record-to-an-object-record)
  below.

Title, ID, and the file are marked with a red asterisk (with a
"* Required" legend at the top of the form); Object Number picks up the
same asterisk only while **Relate this Media record to an existing Object
record** is checked, since it's only required then.

**Create Media record** is visibly greyed out and unclickable until Title,
ID, and a file are all filled in -- and, if **Relate this Media record to an
existing Object record** is checked, until a **Check** of the Object Number
has come back confirming it matches exactly one existing Object record (see
[Checking an Object Number before submitting](#checking-an-object-number-before-submitting)
below). This is purely a client-side convenience to catch problems before
you submit; `create()` still validates everything server-side regardless,
since a browser with JavaScript disabled -- or simply not run -- can't be
relied on to enforce it.

On success, the result page shows the new Media record's CSID and direct
links to the Media record, the Blob record, and the raw file content (and,
if you related it to an Object record, that record's CSID and link too).

## The Contributor field

CollectionSpace's Media schema has a native `contributor` field
(`media_common.xsd` in the [collectionspace/services](https://github.com/collectionspace/services)
source), but out of the box it's a single, plain-text string &mdash; not tied
to any controlled vocabulary. This app restricts it: **Contributor** only
ever offers terms drawn from a fixed set of CollectionSpace **Person**
and/or **Organization Authority** instances, chosen by whoever runs this
app, not the full universe of Person/Organization records in your
tenant. Deliberately scoped to just these two authority *types*, out of
every type CollectionSpace has (Place, Concept, Work, Taxonomy, ...) &mdash;
a Media record's contributor is sensibly either a person or an
organization.

### Configuring the fixed set

CollectionSpace can have many separate instances of each authority type
(see `PersonAuthorityResource.java` / `OrganizationClient.java` in the
services source) &mdash; each instance its own list of terms. The set of
instances Contributor draws from is configured in a YAML file,
`contributor_authorities.yaml`, checked into this repo next to `app.py`
(override the path with `CONTRIBUTOR_AUTHORITIES_CONFIG_PATH`, see
[Setup](#setup) above). It lists the **shortIdentifiers** of the
instance(s) you want Contributor to draw from &mdash; not their display
names &mdash; under two keys:

```yaml
person_authority_instances:
  - photographers
  - donors

organization_authority_instances:
  - institutions
```

You can populate either list alone, or both together &mdash; every term in
every listed instance of either type becomes a selectable Contributor,
merged into one combined list. Leave both empty (the default) and the
field is simply unavailable, the same way "relate to Object" is
unavailable to an account without its required permissions &mdash; the rest
of the app still works. If you're not sure what an instance's
shortIdentifier is, `curl` its authority type's list endpoint (e.g.
`GET /personauthorities`) and match the `<displayName>` you recognize to
the `<shortIdentifier>` next to it &mdash; the shipped
`contributor_authorities.yaml` has this command spelled out in its
comments.

This file is meant to be committed to the repo and shared by the whole
team, rather than each person setting matching environment variables
individually, so everyone who runs the app sees the same Contributor
choices by default. It's read fresh on every page load &mdash; an edit
takes effect the next time someone loads the form, no app restart
needed. Lines starting with `#` are comments and are ignored.

**Permission required:** the logged-in account also needs `R` (read) on
whichever of the `personauthorities` / `orgauthorities` resources
actually has instances configured &mdash; an account with only
`person_authority_instances` populated is never required to also have
Organization Authority read access, and vice versa. This is checked
(like the relate-to-Object permissions) once per page load via
`check_contributor_feature_availability()` in `app.py`, sharing a single
`/accounts/0/accountperms` fetch across every check it needs. If either
the configuration or a required permission is missing, the Contributor
field is disabled and the page explains why (naming each missing
permission separately if more than one is missing), in the same
`permission-warning` style as the Object Number field.

### Typing a Contributor

Contributor is a type-ahead text field, not a plain dropdown: start typing
a name and matching suggestions appear, built from every term in the
configured Person/Organization Authority instances. It's still not free
text, though &mdash; the visible field only ever accepts a whole, exact
suggestion. If what's currently typed doesn't exactly match one of them
(case-insensitively), the field shows "No configured Contributor matches
&hellip;" and **Create Media record** stays disabled, the same way an
unconfirmed Object Number blocks submission &mdash; this catches a
half-typed name before it can be silently submitted as "no Contributor"
instead of what you actually meant to pick. Clearing the field back to
empty is always fine; that's a valid "no Contributor" choice.

### How a selection is stored

Contributor isn't free text and isn't a display name &mdash; picking a
suggestion stores that term's full CollectionSpace **refName**, e.g.:

```
urn:cspace:core.collectionspace.org:personauthorities:name(photographers):item:name(janedoe)'Jane Doe'
```

This is deliberate: two different instances &mdash; of the same authority
type, or one Person and one Organization &mdash; can each have a term called,
say, "Jane Doe," and a bare display name can't tell them apart. The
refName can. The field's suggestions disambiguate the same way &mdash;
`"Jane Doe &mdash; Photographers"` vs. `"Jane Doe &mdash; Donors"` vs.
`"Jane Doe &mdash; Institutions"` &mdash; built from each term's own
`termDisplayName` plus its parent authority instance's `displayName`. (The
term-level field is named `termDisplayName` in the CollectionSpace source,
not `displayName` &mdash; that plain name is specific to the separate
Vocabulary service's item lists. `fetch_authority_items()` in `app.py`
checks `termDisplayName` first, falling back to `displayName` only for
older CollectionSpace versions that may still emit it.) Behind the scenes,
picking a suggestion fills a hidden `contributor` form field with the
matching refName &mdash; the visible text field itself is never what's
submitted.

**Important caveat:** storing a well-formed refName here makes the value
correct and unambiguous, but it does *not*, by itself, make CollectionSpace's
own UI treat `contributor` as a live, clickable authority reference (e.g.
showing this Media record under that Person or Organization's "used by"
list). That additionally requires your CollectionSpace tenant's service
bindings to mark `media:contributor` as an authority-reference field
pointing at `personauthority` and/or `orgauthority` &mdash; a CollectionSpace
configuration change made outside this app, in your tenant bindings, not
something this app can do for you. Without that configuration,
CollectionSpace still stores the value this app sends (a syntactically
valid refName), it just won't be treated as a formal, resolvable link by
CollectionSpace's own screens.

Only one Contributor can be set per Media record &mdash; matching the stock
schema's single, non-repeatable `contributor` field. Supporting more than
one would require your CollectionSpace tenant's schema to be customized
to make it repeatable, which is beyond what this app's own code controls.

### Validation

Like Object Number, the Contributor field only ever submits a refName
drawn from the fixed, configured set &mdash; typed text that doesn't exactly
match a suggestion is blocked client-side (see
[Typing a Contributor](#typing-a-contributor) above) rather than
submitted as free text. But `create()` never trusts that alone: it re-runs
`check_contributor_feature_availability()` and re-fetches the current,
combined Person+Organization term list via `fetch_contributor_choices()`
at submit time, and rejects the submission (creating nothing) if the
submitted refName doesn't exactly match a term in that fresh fetch &mdash;
covering a permission revoked, an instance reconfigured, or a term
deleted between page load and submission, not just a tampered request.

## Relating a Media record to an Object record

**Relate this Media record to an existing Object record** and its
**Object Number** field only appear enabled if your account has both
permissions this feature needs: `R` (read) on the `collectionobjects`
resource, needed to look the Object Number up, and `C` (create) on the
`relations` resource, needed to create the link. This is checked once
per page load, using the same `/accounts/0/accountperms` data and
unioning-across-roles logic as the Media permissions check in
[Logging in](#logging-in) (see `check_relate_to_object_permissions()` in
`app.py`, which shares a single accountperms fetch between both
sub-checks). If either permission is missing, the checkbox and Object
Number field are both disabled, and the page shows which permission(s)
are missing in place of the usual hint text, so you don't fill in an
Object Number only to have the submission rejected. This check (like the
Media check at login) doesn't block the rest of the app -- an account
that can't search Object records or create relations still logs in fine
and can still create ordinary (unrelated) Media records; it just can't
use this one feature.

### Checking an Object Number before submitting

Next to the Object Number field is a **Check** button (enabled under the
same conditions as the field itself). Clicking it looks the number up
immediately -- via a small AJAX call to `GET /check_object_number`, a
read-only endpoint that does nothing but run the very same
`find_collectionobject_by_number()` lookup `create()` itself uses at
submit time -- and shows the result right there ("Object record found"
or an explanation of why not) without submitting the rest of the form or
leaving the page. This is a convenience, not a guarantee: the result
only reflects that one Object Number at that moment, so editing the
field afterwards clears the shown result, and the real submission always
re-checks the number itself rather than trusting a stale "found".

Whenever **Relate this Media record to an existing Object record** is
checked, a successful Check for the Object Number currently in the field
is also what unlocks **Create Media record** -- so you can't submit with
an Object Number you haven't confirmed exists. Editing the Object Number
after checking it, or checking the box before running a Check at all,
re-locks the button until Check is run again and comes back with a
match. Unchecking the box drops this requirement immediately (Title, ID,
and a file are still required either way).

The same check runs again when you submit the form, in case your
account's permissions changed between loading the page and submitting
(a role was revoked, for instance) -- disabling the field client-side is
a convenience, not the only place this is enforced. Checking
**Relate this Media record to an existing Object record** and entering
an **Object Number** adds these steps, all before the Media and Blob
records are created:

1. The app re-confirms the same two permissions described above (via
   `check_relate_to_object_permissions()`). If either is missing, both
   problems are reported together rather than making you fix one and
   then discover the other.
2. The app looks up the Object Number with
   `GET /collectionobjects?as=collectionobjects_common:objectNumber = '...'`
   &mdash; CollectionSpace's generic "advanced search" query mechanism, scoped
   to an exact match on that one field. If it doesn't match exactly one
   Object record (zero matches, or more than one &mdash; `objectNumber` isn't
   guaranteed unique in every tenant configuration), the submission is
   rejected with an error and nothing is created.

Both steps run before the Media record is created, specifically so a
missing permission or a bad Object Number can never leave behind an
orphaned, unrelated Media record. Only after both pass do the Media and
Blob records get created as usual (steps 1 and 2 in the sequence above),
followed by **two** `POST /relations` calls to link the new Media record
to the Object record -- one with the Media record as subject and the
Object record as object, and a second with them reversed -- using
predicate `affects` &mdash; the same generic, non-hierarchical
relationship type CollectionSpace's own UI uses for this kind of "related
record" association.

**Why two, not one:** CollectionSpace's "related records" panel for a
given record only ever queries relations where *that record* is the
subject (confirmed from the `application` repo's source:
`RecordRelated.store_get()` queries `GET /relations?sbj=<thisRecord>`,
never with `andReciprocal`). A single relation record -- say, Media as
subject, Object as object -- is a perfectly valid document, and will
show up on the *Media* record's related-records view, but never on the
*Object* record's, which is usually the one you're actually checking
afterwards. CollectionSpace's own web application handles this by always
creating a relation in both directions whenever you relate two records
through it (see `RelateCreateUpdate.relate()`), and this app does the
same, via `create_reciprocal_relations()` in `app.py`.

If one or both of those two `POST /relations` calls fails (a permission
was revoked between the check and the call, a transient network error,
the Object record was deleted in the meantime, and so on), the result
page still reports success for the Media and Blob records -- your
upload isn't lost over a problem with this last step -- but the
incomplete relation is called out in its own amber "Note" box, separate
from (and below) the green success message, rather than folded into it
as one more sentence. The note also says which single direction (if
any) did get created, so you know which one record's related-records
view it'll actually show up on in the meantime. It's easy to miss a
problem that's buried in a success message; an incomplete relation is
not something this app wants you to have to notice on your own.

### If a relation doesn't show up in CollectionSpace

If you're not seeing an expected relation in CollectionSpace after a
run that the app reported as a full success (no amber "Note" box), the
most direct way to check is independent of any particular CollectionSpace
screen: run the included `check_relation.py` script against the Media
record's CSID (shown on the result page) and, when prompted, also give
it the Object record's CSID to check both directions at once:

```bash
python3 check_relation.py
```

It queries `GET /relations?sbj=<csid>&andReciprocal=true` directly --
the same query `create_relation()` in `app.py` relies on CollectionSpace
to process correctly, just without any UI in between that might filter,
group, or simply not surface it the way you expect -- and, when you give
it both CSIDs, tells you plainly whether the Forward direction, the
Reverse direction, both, or neither actually exist.

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
