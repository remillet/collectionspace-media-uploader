"""
CollectionSpace Media + Blob Uploader
======================================

A small Flask web app that creates a CollectionSpace Media record and
links an uploaded photo/document to it as a Blob record, using the
two-step flow documented in the CollectionSpace Technical Documentation
(Media Service REST APIs):

    1. POST /media                  -> creates the Media record (metadata only)
    2. PUT  /media/{csid}/blob      -> uploads the file, creating a Blob
                                        record and linking it to the Media
                                        record from step 1

Logging in:
    The CollectionSpace REST API itself is stateless -- every call is
    authenticated independently via HTTP Basic Auth, with no server-side
    session or login/logout endpoint of its own (see the CollectionSpace
    Common Services REST API docs). This app builds a login on top of
    that: you enter your CollectionSpace instance URL and credentials
    once, we verify them with a lightweight authenticated call, and then
    we keep an app-level (Flask) session for you so you don't have to
    re-enter them for every upload.

    Your CollectionSpace username/password are never put in the Flask
    session cookie. They're stored in AWS Secrets Manager for the
    duration of your login and fetched fresh, per request, whenever this
    app needs to make a CollectionSpace API call on your behalf -- never
    cached in a global variable. The session cookie only holds a
    reference (the secret's name) plus non-sensitive display info (your
    username, the instance URL). Logging out deletes the secret.

    This requires AWS credentials to be available to the app in the usual
    ways boto3 looks for them (environment variables, ~/.aws/credentials,
    an EC2/ECS/Lambda instance role, etc.), with permission to create,
    read, and delete secrets under the "collectionspace-uploader/session/*"
    name prefix. See README.md for the exact IAM actions needed.

Run:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000 in a browser.

Security notes:
    - Your CollectionSpace password is used only to make the API calls
      described above and to populate a short-lived AWS Secrets Manager
      secret. It is never logged or written to local disk.
    - Only use this against a CollectionSpace instance and account you
      control and trust.
    - SSL certificate verification is ON by default. Only disable it for
      a self-hosted/sandbox instance with a self-signed certificate that
      you trust.
    - Known limitation: if a browser closes without visiting "Log out",
      its Secrets Manager secret is not automatically cleaned up --
      Flask's cookie-based sessions have no server-side expiry hook to
      trigger that. For anything beyond local/personal use, pair this
      with a scheduled job that deletes secrets under the session prefix
      older than, say, 24 hours.
    - debug=True (below) enables the Werkzeug interactive debugger. That
      was already true before this change and is unrelated to the login
      work, but it's worth repeating: never run this with debug mode on
      anywhere but localhost.
"""

import json
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import wraps
from xml.sax.saxutils import escape

import boto3
from botocore.exceptions import BotoCoreError, ClientError
import requests
from flask import Flask, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload cap

# Flask uses this key to sign the session cookie. Set FLASK_SECRET_KEY in
# your environment for a stable key across restarts; without it, every
# restart generates a new random key and invalidates existing logins --
# a fine trade-off for local/personal use, not for a shared deployment.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Flip this on once the app is served over HTTPS. Left on while served
# over plain HTTP (e.g. local dev on 127.0.0.1), the browser will
# silently refuse to send the cookie back and login will appear to "not
# stick".
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_SESSION_COOKIE_SECURE") == "1"

SECRET_NAME_PREFIX = "collectionspace-uploader/session"
_secrets_client = None


def secrets_client():
    """Lazily create (and reuse) the boto3 Secrets Manager client."""
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client(
            "secretsmanager", region_name=os.environ.get("AWS_REGION")
        )
    return _secrets_client


# --- Credential storage (AWS Secrets Manager) ------------------------------
#
# The CollectionSpace username/password are never put in the Flask session
# cookie -- only a *reference* to a Secrets Manager secret goes there. The
# password itself is fetched fresh for each API call rather than cached,
# so deleting the secret (logout) takes effect on the very next request.

def store_login_secret(instance_url: str, username: str, password: str, verify_ssl: bool) -> str:
    """Create a new Secrets Manager secret for this login. Returns its name."""
    secret_name = f"{SECRET_NAME_PREFIX}/{uuid.uuid4().hex}"
    payload = {
        "instance_url": instance_url,
        "username": username,
        "password": password,
        "verify_ssl": verify_ssl,
    }
    secrets_client().create_secret(
        Name=secret_name,
        SecretString=json.dumps(payload),
        Description=(
            "Transient CollectionSpace login for the Media Uploader app "
            f"(user: {username}, created {datetime.now(timezone.utc).isoformat()}). "
            "Safe to delete once the owning browser session has ended."
        ),
    )
    return secret_name


def load_login_secret(secret_name: str) -> dict:
    """Fetch this login's CollectionSpace credentials for a single API call."""
    response = secrets_client().get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def delete_login_secret(secret_name: str) -> None:
    """Remove a login's credentials from Secrets Manager on logout."""
    secrets_client().delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)


def login_required(view):
    """Redirect to /login if this browser doesn't have an active login."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "cs_secret_name" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CollectionSpace Media Uploader &mdash; Log in</title>
  <style>
    body { font-family: sans-serif; max-width: 560px; margin: 40px auto; padding: 0 16px; color: #1c1e21; }
    label { display: block; margin-top: 14px; font-weight: 600; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px;
    }
    button {
      margin-top: 22px; padding: 10px 22px; border: none; border-radius: 6px;
      background: #2563eb; color: white; font-size: 1em; cursor: pointer;
    }
    button:hover { background: #1d4ed8; }
    .hint { color: #666; font-size: 0.85em; margin-top: 2px; }
    .checkbox-row { margin-top: 16px; }
    .checkbox-row label { display: inline; font-weight: normal; margin-left: 6px; }
    code { background: #f1f3f5; padding: 1px 5px; border-radius: 3px; }
    ul.errors { background: #fdecea; padding: 12px 24px; border-radius: 6px; word-break: break-word; color: #b3261e; }
  </style>
</head>
<body>
  <h1>Log in to CollectionSpace</h1>
  <p>
    Enter your CollectionSpace instance and credentials once. We'll verify
    them, then keep you logged in for this browser session so you don't
    have to re-enter your password for every upload.
  </p>

  {% if errors %}
    <ul class="errors">
      {% for e in errors %}<li>{{ e }}</li>{% endfor %}
    </ul>
  {% endif %}

  <form action="{{ url_for('login') }}" method="post">
    <label for="instance_url">CollectionSpace instance URL</label>
    <input type="text" id="instance_url" name="instance_url"
           placeholder="https://myinstance.collectionspace.org" required
           value="{{ instance_url or '' }}">
    <div class="hint">Base URL only &mdash; <code>/cspace-services</code> is added automatically if missing.</div>

    <label for="username">CollectionSpace username</label>
    <input type="text" id="username" name="username" autocomplete="username" required
           value="{{ username or '' }}">

    <label for="password">CollectionSpace password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>

    <div class="checkbox-row">
      <input type="checkbox" id="verify_ssl" name="verify_ssl" {% if verify_ssl %}checked{% endif %}>
      <label for="verify_ssl">Verify SSL certificate (uncheck only for self-signed dev/sandbox instances)</label>
    </div>

    <button type="submit">Log in</button>
  </form>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CollectionSpace Media Uploader</title>
  <style>
    body { font-family: sans-serif; max-width: 560px; margin: 40px auto; padding: 0 16px; color: #1c1e21; }
    label { display: block; margin-top: 14px; font-weight: 600; }
    input[type=text], input[type=file] {
      width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px;
    }
    button {
      margin-top: 22px; padding: 10px 22px; border: none; border-radius: 6px;
      background: #2563eb; color: white; font-size: 1em; cursor: pointer;
    }
    button:hover { background: #1d4ed8; }
    .hint { color: #666; font-size: 0.85em; margin-top: 2px; }
    code { background: #f1f3f5; padding: 1px 5px; border-radius: 3px; }
    .nav { background: #eef2ff; border-radius: 6px; padding: 8px 14px; margin-bottom: 20px; font-size: 0.9em; }
    .nav a { color: #2563eb; }
  </style>
</head>
<body>
  <div class="nav">
    Logged in as <strong>{{ username }}</strong> &middot; {{ instance_url }}
    &middot; <a href="{{ url_for('logout') }}">Log out</a>
  </div>

  <h1>Create a CollectionSpace Media record</h1>
  <p>
    This creates a Media record and links an uploaded file to it as a Blob
    record, via <code>POST /media</code> followed by
    <code>PUT /media/{csid}/blob</code>.
  </p>

  <form action="{{ url_for('create') }}" method="post" enctype="multipart/form-data">
    <label for="title">Title</label>
    <input type="text" id="title" name="title" required>

    <label for="identification_number">ID</label>
    <input type="text" id="identification_number" name="identification_number" required>

    <label for="file">Photo or document to upload</label>
    <input type="file" id="file" name="file" required>

    <button type="submit">Create Media record</button>
  </form>
</body>
</html>
"""

RESULT_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CollectionSpace Media Uploader &mdash; Result</title>
  <style>
    body { font-family: sans-serif; max-width: 560px; margin: 40px auto; padding: 0 16px; color: #1c1e21; }
    .ok { color: #1a7f37; }
    .fail { color: #b3261e; }
    ul.errors { background: #fdecea; padding: 12px 24px; border-radius: 6px; word-break: break-word; }
    dl { background: #f4f6f8; padding: 12px 20px; border-radius: 6px; }
    dt { font-weight: 600; margin-top: 8px; }
    dd { margin-left: 0; word-break: break-all; }
    a.back { display: inline-block; margin-top: 24px; }
    .nav { background: #eef2ff; border-radius: 6px; padding: 8px 14px; margin-bottom: 20px; font-size: 0.9em; }
    .nav a { color: #2563eb; }
  </style>
</head>
<body>
  {% if username %}
    <div class="nav">
      Logged in as <strong>{{ username }}</strong> &middot; {{ instance_url }}
      &middot; <a href="{{ url_for('logout') }}">Log out</a>
    </div>
  {% endif %}

  {% if success %}
    <h1 class="ok">Success</h1>
  {% else %}
    <h1 class="fail">Something went wrong</h1>
  {% endif %}
  <p>{{ message }}</p>

  {% if errors %}
    <ul class="errors">
      {% for e in errors %}<li>{{ e }}</li>{% endfor %}
    </ul>
  {% endif %}

  {% if details %}
    <dl>
      {% for k, v in details.items() %}
        <dt>{{ k }}</dt><dd>{{ v }}</dd>
      {% endfor %}
    </dl>
  {% endif %}

  <a class="back" href="{{ url_for('index') }}">&larr; Create another</a>
</body>
</html>
"""


def normalize_base_url(raw_url: str) -> str:
    """Turn whatever the user typed into a usable cspace-services base URL."""
    url = raw_url.strip().rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    if not url.endswith("/cspace-services"):
        url = url + "/cspace-services"
    return url


def build_media_payload(title: str, identification_number: str) -> bytes:
    """Build the XML body for POST /media (media_common part only)."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<document name="media">\n'
        '<ns2:media_common xmlns:ns2="http://collectionspace.org/services/media">\n'
        f"  <title>{escape(title)}</title>\n"
        f"  <identificationNumber>{escape(identification_number)}</identificationNumber>\n"
        "</ns2:media_common>\n"
        "</document>"
    )
    return xml.encode("utf-8")


def verify_collectionspace_login(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm a username/password pair is a valid CollectionSpace login.

    Uses GET /accounts/0/accountperms -- "0" is a real, deliberate sentinel
    in the CollectionSpace services source (see
    JpaStorageUtils.CS_CURRENT_USER, and its use in getAccountValue()) that
    resolves to "whichever account is currently authenticated" rather than
    a literal account csid. That makes this a self-service "my own
    permissions" call: the underlying authorization check only runs when
    the target account differs from the caller, which csid=0 guarantees it
    never does -- so any valid account gets a clean 200 back, regardless
    of whether it has rights to do anything else (e.g. list all accounts).

    Returns (True, None) on success, or (False, error_message) on failure.
    """
    accountperms_url = f"{base_url}/accounts/0/accountperms"
    try:
        resp = requests.get(
            accountperms_url,
            auth=(username, password),
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return False, f"Could not reach {base_url} to verify your login: {exc}"

    if resp.status_code == 401:
        return False, "Invalid username or password for that CollectionSpace instance."
    if resp.status_code == 404:
        return False, (
            "Couldn't find the CollectionSpace accounts service at that URL "
            "-- double-check the instance URL."
        )
    if resp.status_code >= 500:
        return False, f"The CollectionSpace instance returned a server error (HTTP {resp.status_code})."

    # Any other response (200, in practice) means the credentials were
    # accepted -- /accounts/0/accountperms always resolves to the caller's
    # own account, so there's no permission-dependent status code to hedge
    # against here.
    return True, None


# Action-group letter codes (from CollectionSpace's ActionType/ActionGroup)
# that this app needs on the "media" resource, and what each one is for.
REQUIRED_MEDIA_ACTIONS = {
    "C": "create Media records (POST /media)",
    "U": "attach uploaded files as Blob records (PUT /media/{csid}/blob)",
}


def _local_tag(tag: str) -> str:
    """Strip an XML namespace, e.g. '{http://...}permission' -> 'permission'."""
    return tag.rsplit("}", 1)[-1]


def _find_child(element, local_name: str):
    """First direct child of element whose (namespace-stripped) tag matches."""
    for child in element:
        if _local_tag(child.tag) == local_name:
            return child
    return None


def verify_media_permissions(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm the account can create Media records and attach Blob files.

    Calls the same GET /accounts/0/accountperms endpoint used to verify
    login (see verify_collectionspace_login), but this time parses the
    response body instead of only checking the status code.

    /accounts/0/accountperms returns an <account_permission> document
    with one <permission> element per permission-role relationship the
    account holds (see AccountPermission.java / PermissionValue.java in
    the CollectionSpace services source) -- so an account's access to a
    given resource can be split across more than one entry, if more than
    one of its roles grants access to that resource. Each entry has a
    <resourceName> and an <actionGroup>, a string of one-letter action
    codes (C=create, R=read, U=update, D=delete, L=search/list, I=run).

    Both calls this app makes are checked against the SAME resource,
    "media" -- /media/{csid}/blob collapses to its parent resource for
    authorization purposes (see SecurityUtils.java in the CollectionSpace
    services source):
        POST /media               -> action CREATE -> resource "media"
        PUT  /media/{csid}/blob   -> action UPDATE  -> resource "media"

    So this unions the actionGroup letters across every <permission>
    entry for resourceName == "media" and confirms both 'C' and 'U' are
    present, rather than requiring a single entry to contain both.

    Returns (True, None) if the account has both permissions, or
    (False, error_message) describing what's missing, or what went wrong
    making or parsing the request.
    """
    accountperms_url = f"{base_url}/accounts/0/accountperms"
    try:
        resp = requests.get(
            accountperms_url,
            auth=(username, password),
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return False, f"Could not reach {base_url} to check your permissions: {exc}"

    if resp.status_code == 401:
        return False, "Invalid username or password for that CollectionSpace instance."
    if resp.status_code >= 400:
        return False, (
            "Couldn't retrieve your account permissions "
            f"(HTTP {resp.status_code}) from {accountperms_url}."
        )

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        return False, f"Couldn't parse the permissions response from CollectionSpace: {exc}"

    media_action_group = set()
    for element in root.iter():
        if _local_tag(element.tag) != "permission":
            continue
        resource_name_el = _find_child(element, "resourceName")
        action_group_el = _find_child(element, "actionGroup")
        if resource_name_el is None or action_group_el is None:
            continue
        if (resource_name_el.text or "").strip() != "media":
            continue
        media_action_group.update((action_group_el.text or "").strip())

    missing = [
        action for action in REQUIRED_MEDIA_ACTIONS if action not in media_action_group
    ]
    if missing:
        missing_descriptions = "; ".join(REQUIRED_MEDIA_ACTIONS[a] for a in missing)
        return False, (
            "Your CollectionSpace account doesn't have permission to "
            f"{missing_descriptions}. Ask a CollectionSpace administrator "
            "to grant a role with create/update access to Media records."
        )

    return True, None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(
            LOGIN_TEMPLATE, errors=None, instance_url="", username="", verify_ssl=True
        )

    instance_url = request.form.get("instance_url", "")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    verify_ssl = request.form.get("verify_ssl") == "on"

    errors = []
    if not instance_url.strip():
        errors.append("CollectionSpace instance URL is required.")
    if not username.strip():
        errors.append("Username is required.")
    if not password:
        errors.append("Password is required.")

    if errors:
        return (
            render_template_string(
                LOGIN_TEMPLATE,
                errors=errors,
                instance_url=instance_url,
                username=username,
                verify_ssl=verify_ssl,
            ),
            400,
        )

    base_url = normalize_base_url(instance_url)
    ok, error = verify_collectionspace_login(base_url, username, password, verify_ssl)
    if not ok:
        return (
            render_template_string(
                LOGIN_TEMPLATE,
                errors=[error],
                instance_url=instance_url,
                username=username,
                verify_ssl=verify_ssl,
            ),
            401,
        )

    ok, error = verify_media_permissions(base_url, username, password, verify_ssl)
    if not ok:
        return (
            render_template_string(
                LOGIN_TEMPLATE,
                errors=[error],
                instance_url=instance_url,
                username=username,
                verify_ssl=verify_ssl,
            ),
            403,
        )

    try:
        secret_name = store_login_secret(base_url, username, password, verify_ssl)
    except (BotoCoreError, ClientError) as exc:
        return (
            render_template_string(
                LOGIN_TEMPLATE,
                errors=[
                    "Your credentials checked out, but we couldn't securely "
                    f"store them right now (AWS Secrets Manager error: {exc}). "
                    "Check that AWS credentials are configured for this app "
                    "and try again."
                ],
                instance_url=instance_url,
                username=username,
                verify_ssl=verify_ssl,
            ),
            502,
        )

    session.clear()
    session["cs_secret_name"] = secret_name
    session["cs_username"] = username
    session["cs_instance_url"] = base_url
    return redirect(url_for("index"))


@app.route("/logout", methods=["GET"])
def logout():
    secret_name = session.get("cs_secret_name")
    if secret_name:
        try:
            delete_login_secret(secret_name)
        except (BotoCoreError, ClientError):
            # Best-effort: still clear the local session even if Secrets
            # Manager cleanup fails, so the user isn't stuck logged in.
            pass
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template_string(
        INDEX_TEMPLATE,
        username=session.get("cs_username"),
        instance_url=session.get("cs_instance_url"),
    )


@app.route("/create", methods=["POST"])
@login_required
def create():
    try:
        creds = load_login_secret(session["cs_secret_name"])
    except (BotoCoreError, ClientError):
        # The secret's gone or unreachable -- treat this the same as a
        # logout rather than surfacing a raw AWS error mid-upload.
        session.clear()
        return redirect(url_for("login"))

    base_url = creds["instance_url"]
    auth = (creds["username"], creds["password"])
    verify_ssl = creds["verify_ssl"]

    title = request.form.get("title", "")
    identification_number = request.form.get("identification_number", "")
    uploaded_file = request.files.get("file")

    errors = []
    if not title.strip():
        errors.append("Title is required.")
    if not identification_number.strip():
        errors.append("ID is required.")
    if uploaded_file is None or uploaded_file.filename == "":
        errors.append("A file to upload is required.")

    if errors:
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message="Please fix the following and try again:",
                errors=errors,
                details=None,
                username=creds["username"],
                instance_url=base_url,
            ),
            400,
        )

    # --- Step 1: create the Media record (metadata only) ---
    media_url = f"{base_url}/media"
    payload = build_media_payload(title, identification_number)
    try:
        create_resp = requests.post(
            media_url,
            data=payload,
            headers={"Content-Type": "application/xml"},
            auth=auth,
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message="Could not reach the CollectionSpace instance to create the Media record.",
                errors=[str(exc)],
                details={"media_url": media_url},
                username=creds["username"],
                instance_url=base_url,
            ),
            502,
        )

    if create_resp.status_code != 201:
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message=f"Creating the Media record failed (HTTP {create_resp.status_code}).",
                errors=[create_resp.text[:2000] or "(no response body)"],
                details={"media_url": media_url},
                username=creds["username"],
                instance_url=base_url,
            ),
            502,
        )

    location = create_resp.headers.get("Location", "")
    media_csid = location.rstrip("/").split("/")[-1]
    if not media_csid:
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message="The Media record was created, but no CSID was returned in the Location header.",
                errors=[f"Location header received: {location!r}"],
                details=None,
                username=creds["username"],
                instance_url=base_url,
            ),
            502,
        )

    # --- Step 2: upload the file, creating and linking the Blob record ---
    blob_url = f"{base_url}/media/{media_csid}/blob"
    file_bytes = uploaded_file.read()
    files = {
        "file": (
            uploaded_file.filename,
            file_bytes,
            uploaded_file.mimetype or "application/octet-stream",
        )
    }
    try:
        blob_resp = requests.put(
            blob_url,
            files=files,
            auth=auth,
            verify=verify_ssl,
            timeout=120,
        )
    except requests.exceptions.RequestException as exc:
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message=(
                    f"The Media record ({media_csid}) was created, but uploading "
                    "the file failed."
                ),
                errors=[str(exc)],
                details={"media_csid": media_csid, "media_url": f"{base_url}/media/{media_csid}"},
                username=creds["username"],
                instance_url=base_url,
            ),
            502,
        )

    # PUT /media/{csid}/blob is handled server-side by MediaResource.createBlob(),
    # which returns the response from creating the *Blob* resource (not the Media
    # update) -- so a successful call legitimately returns 201 Created, not 200.
    if blob_resp.status_code not in (200, 201):
        return (
            render_template_string(
                RESULT_TEMPLATE,
                success=False,
                message=(
                    f"The Media record ({media_csid}) was created, but linking the "
                    f"Blob failed (HTTP {blob_resp.status_code})."
                ),
                errors=[blob_resp.text[:2000] or "(no response body)"],
                details={"media_csid": media_csid, "media_url": f"{base_url}/media/{media_csid}"},
                username=creds["username"],
                instance_url=base_url,
            ),
            502,
        )

    return render_template_string(
        RESULT_TEMPLATE,
        success=True,
        message="Media record created and file uploaded and linked successfully.",
        errors=None,
        details={
            "media_csid": media_csid,
            "media_record": f"{base_url}/media/{media_csid}",
            "blob_record": f"{base_url}/media/{media_csid}/blob",
            "blob_content": f"{base_url}/media/{media_csid}/blob/content",
        },
        username=creds["username"],
        instance_url=base_url,
    )


if __name__ == "__main__":
    app.run(debug=True)
