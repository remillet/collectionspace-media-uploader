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
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for

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
    button:disabled, button:disabled:hover {
      background: #a9b0bc; color: #eef1f4; cursor: not-allowed;
    }
    .required { color: #b3261e; }
    .hint { color: #666; font-size: 0.85em; margin-top: 2px; }
    code { background: #f1f3f5; padding: 1px 5px; border-radius: 3px; }
    .nav { background: #eef2ff; border-radius: 6px; padding: 8px 14px; margin-bottom: 20px; font-size: 0.9em; }
    .nav a { color: #2563eb; }
    .checkbox-row { margin-top: 18px; }
    .checkbox-row label { display: inline; font-weight: normal; margin-left: 6px; }
    .permission-warning {
      color: #b3261e; background: #fdecea; border-radius: 6px;
      padding: 10px 14px; margin-top: 6px; font-size: 0.85em;
    }
    .permission-warning ul { margin: 6px 0 0; padding-left: 20px; }
    .object-number-row { display: flex; gap: 8px; align-items: flex-start; }
    .object-number-row input[type=text] { flex: 1; }
    .object-number-row button {
      margin-top: 4px; padding: 8px 14px; border: 1px solid #2563eb; border-radius: 4px;
      background: white; color: #2563eb; font-size: 0.9em; cursor: pointer; white-space: nowrap;
    }
    .object-number-row button:hover { background: #eef2ff; }
    .object-number-row button:disabled {
      border-color: #ccc; color: #999; cursor: not-allowed; background: #f4f6f8;
    }
    .check-result { font-size: 0.85em; margin-top: 4px; min-height: 1.2em; }
    .check-result-ok { color: #1a7f37; }
    .check-result-fail { color: #b3261e; }
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
    <p class="hint"><span class="required" aria-hidden="true">*</span> Required</p>

    <label for="title">Title <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="title" name="title" required>

    <label for="identification_number">ID <span class="required" aria-hidden="true">*</span></label>
    <input type="text" id="identification_number" name="identification_number" required>

    <label for="file">Photo or document to upload <span class="required" aria-hidden="true">*</span></label>
    <input type="file" id="file" name="file" required>

    <div class="checkbox-row">
      <input type="checkbox" id="relate_to_object" name="relate_to_object"{% if not can_relate_to_object %} disabled{% endif %}>
      <label for="relate_to_object">Relate this Media record to an existing Object record</label>
    </div>

    <label for="object_number">Object Number <span class="required" id="object_number_required" aria-hidden="true" style="display: none;">*</span></label>
    <div class="object-number-row">
      <input type="text" id="object_number" name="object_number" placeholder="e.g. 2024.1.1"{% if not can_relate_to_object %} disabled{% endif %}>
      <button type="button" id="check_object_number_btn" onclick="checkObjectNumber()"{% if not can_relate_to_object %} disabled{% endif %}>Check</button>
    </div>
    <div id="object_number_check_result" class="check-result" aria-live="polite"></div>
    {% if can_relate_to_object %}
    <div class="hint">
      Only used if "Relate this Media record to an existing Object record" is
      checked above. We'll look this up in CollectionSpace before creating
      anything, and stop with an error if it doesn't match exactly one
      existing Object record.
    </div>
    {% else %}
    <div class="permission-warning">
      This account can't relate Media records to Object records yet:
      <ul>
        {% for e in relate_permission_errors %}<li>{{ e }}</li>{% endfor %}
      </ul>
    </div>
    {% endif %}

    <button type="submit" id="create_button" disabled>Create Media record</button>
  </form>

  <script>
    const createButton = document.getElementById("create_button");
    const titleInput = document.getElementById("title");
    const identificationNumberInput = document.getElementById("identification_number");
    const fileInput = document.getElementById("file");
    const relateCheckbox = document.getElementById("relate_to_object");
    const objectNumberInput = document.getElementById("object_number");
    const objectNumberResultEl = document.getElementById("object_number_check_result");
    const objectNumberRequiredMarker = document.getElementById("object_number_required");

    // Whether the CURRENT value of Object Number has been confirmed, via a
    // successful Check, to match exactly one existing Object record. Reset
    // to false any time that value changes (below) or a Check comes back
    // anything other than a clean match, so it can never go stale.
    let objectNumberConfirmed = false;

    // Required-fields-filled AND (not relating, or the Object Number has
    // been confirmed) -- both conditions have to hold for the button to be
    // enabled, matching what create() itself requires server-side.
    function updateCreateButtonState() {
      // Object Number is only actually required while relating is turned
      // on, so its "*" only shows then too, rather than marking it
      // required all the time.
      objectNumberRequiredMarker.style.display = relateCheckbox.checked ? "inline" : "none";

      const requiredFieldsFilled =
        titleInput.value.trim() !== "" &&
        identificationNumberInput.value.trim() !== "" &&
        fileInput.files.length > 0;

      const relateSatisfied = !relateCheckbox.checked || objectNumberConfirmed;

      createButton.disabled = !(requiredFieldsFilled && relateSatisfied);
    }

    titleInput.addEventListener("input", updateCreateButtonState);
    identificationNumberInput.addEventListener("input", updateCreateButtonState);
    fileInput.addEventListener("change", updateCreateButtonState);
    relateCheckbox.addEventListener("change", updateCreateButtonState);

    async function checkObjectNumber() {
      const button = document.getElementById("check_object_number_btn");
      const objectNumber = objectNumberInput.value.trim();

      objectNumberResultEl.textContent = "";
      objectNumberResultEl.className = "check-result";
      objectNumberConfirmed = false;
      updateCreateButtonState();

      if (!objectNumber) {
        objectNumberResultEl.textContent = "Enter an Object Number first.";
        objectNumberResultEl.classList.add("check-result-fail");
        return;
      }

      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = "Checking…";

      try {
        const response = await fetch(
          "{{ url_for('check_object_number') }}?object_number=" + encodeURIComponent(objectNumber)
        );
        const data = await response.json();

        if (response.ok && data.found) {
          objectNumberResultEl.textContent = "✓ Object record found (CSID " + data.csid + ").";
          objectNumberResultEl.classList.add("check-result-ok");
          objectNumberConfirmed = true;
        } else {
          objectNumberResultEl.textContent = "✗ " + (data.error || "Object record not found.");
          objectNumberResultEl.classList.add("check-result-fail");
        }
      } catch (err) {
        objectNumberResultEl.textContent = "✗ Couldn't check right now: " + err;
        objectNumberResultEl.classList.add("check-result-fail");
      } finally {
        button.disabled = false;
        button.textContent = originalLabel;
        updateCreateButtonState();
      }
    }

    // A checked Object Number applies only to the value that was checked --
    // clear the result, and un-confirm it, as soon as the user changes it,
    // so a stale "found" can't be mistaken for still current, and can't
    // leave the Create button enabled on unverified grounds.
    objectNumberInput.addEventListener("input", function () {
      objectNumberResultEl.textContent = "";
      objectNumberResultEl.className = "check-result";
      objectNumberConfirmed = false;
      updateCreateButtonState();
    });

    updateCreateButtonState();
  </script>
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
    .warn { color: #92400e; }
    ul.errors { background: #fdecea; padding: 12px 24px; border-radius: 6px; word-break: break-word; }
    ul.warnings { background: #fff7e6; padding: 12px 24px; border-radius: 6px; word-break: break-word; }
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

  {% if warnings %}
    <p class="warn"><strong>Note:</strong></p>
    <ul class="warnings">
      {% for w in warnings %}<li>{{ w }}</li>{% endfor %}
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


def _fetch_account_permission_root(base_url: str, username: str, password: str, verify_ssl: bool):
    """Fetch and parse this account's GET /accounts/0/accountperms response.

    Calls the same endpoint used to verify login (see
    verify_collectionspace_login), and parses the response body rather
    than only checking the status code. Split out from
    _get_account_action_group() so a check that needs more than one
    resource's permissions (see check_relate_to_object_permissions())
    can do this fetch once and inspect the same parsed document for each
    resource, instead of fetching it again per resource.

    Returns (root, None) on success, where root is the parsed
    <account_permission> XML element, or (None, error_message) on a
    network, HTTP, or XML parsing failure.
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
        return None, f"Could not reach {base_url} to check your permissions: {exc}"

    if resp.status_code == 401:
        return None, "Invalid username or password for that CollectionSpace instance."
    if resp.status_code >= 400:
        return None, (
            "Couldn't retrieve your account permissions "
            f"(HTTP {resp.status_code}) from {accountperms_url}."
        )

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        return None, f"Couldn't parse the permissions response from CollectionSpace: {exc}"

    return root, None


def _action_group_for_resource(root, resource_name: str):
    """The union of actionGroup letters across every <permission> entry
    in an already-parsed accountperms document (see
    _fetch_account_permission_root()) for a single resourceName.

    /accounts/0/accountperms returns an <account_permission> document
    with one <permission> element per permission-role relationship the
    account holds (see AccountPermission.java / PermissionValue.java in
    the CollectionSpace services source) -- so an account's access to a
    given resource can be split across more than one entry, if more than
    one of its roles grants access to that resource. Each entry has a
    <resourceName> and an <actionGroup>, a string of one-letter action
    codes (C=create, R=read, U=update, D=delete, L=search/list, I=run).
    This unions those letters across every matching entry, rather than
    requiring a single entry to contain all of them.
    """
    action_group = set()
    for element in root.iter():
        if _local_tag(element.tag) != "permission":
            continue
        resource_name_el = _find_child(element, "resourceName")
        action_group_el = _find_child(element, "actionGroup")
        if resource_name_el is None or action_group_el is None:
            continue
        if (resource_name_el.text or "").strip() != resource_name:
            continue
        action_group.update((action_group_el.text or "").strip())

    return action_group


def _get_account_action_group(base_url: str, username: str, password: str, verify_ssl: bool, resource_name: str):
    """Fetch this account's permitted actions on a single CollectionSpace resource.

    A thin wrapper around _fetch_account_permission_root() +
    _action_group_for_resource(), for callers (like
    verify_media_permissions()) that only ever need one resource's
    permissions and don't need to share the fetch with anything else.

    Returns (action_group, None) on success, where action_group is a
    (possibly empty) set of the account's permitted action letters for
    resource_name, or (None, error_message) on a network, HTTP, or XML
    parsing failure.
    """
    root, error = _fetch_account_permission_root(base_url, username, password, verify_ssl)
    if error:
        return None, error

    return _action_group_for_resource(root, resource_name), None


def verify_media_permissions(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm the account can create Media records and attach Blob files.

    Both calls this app makes for that are checked against the SAME
    resource, "media" -- /media/{csid}/blob collapses to its parent
    resource for authorization purposes (see SecurityUtils.java in the
    CollectionSpace services source):
        POST /media               -> action CREATE -> resource "media"
        PUT  /media/{csid}/blob   -> action UPDATE  -> resource "media"

    Returns (True, None) if the account has both 'C' and 'U' on "media",
    or (False, error_message) describing what's missing, or what went
    wrong making or parsing the request.
    """
    media_action_group, error = _get_account_action_group(base_url, username, password, verify_ssl, "media")
    if error:
        return False, error

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


def _check_relation_create_permission(relations_action_group):
    """None if relations_action_group includes 'C', else the standard
    "can't create relations" error message.

    Split out from verify_relation_permissions() so
    check_relate_to_object_permissions() can apply the exact same check
    (and wording) to an action group it derived from an
    already-fetched accountperms document, instead of fetching it again.
    """
    if "C" in relations_action_group:
        return None
    return (
        "Your CollectionSpace account doesn't have permission to create "
        "relations (POST /relations), so it can't relate a Media record "
        "to an Object record. Ask a CollectionSpace administrator to "
        "grant a role with create access to Relation records."
    )


def _check_collectionobject_read_permission(collectionobject_action_group):
    """None if collectionobject_action_group includes 'R', else the
    standard "can't read/search Object records" error message.

    Split out from verify_collectionobject_search_permissions() for the
    same reason as _check_relation_create_permission() above.
    """
    if "R" in collectionobject_action_group:
        return None
    return (
        "Your CollectionSpace account doesn't have permission to read or "
        "search Object records (GET /collectionobjects), so it can't look "
        "up an Object Number to relate a Media record to. Ask a "
        "CollectionSpace administrator to grant a role with read access "
        "to Object records."
    )


def verify_relation_permissions(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm the account can create Relation records (POST /relations).

    Checked separately from verify_media_permissions(), and only when the
    "relate to an Object record" checkbox is used, rather than at login
    for every account -- most logins never touch this feature, so there's
    no reason to require every account to have this permission just to
    log in.

    Returns (True, None) if the account has 'C' on "relations", or
    (False, error_message) otherwise (or on a network/parsing failure).
    """
    relations_action_group, error = _get_account_action_group(
        base_url, username, password, verify_ssl, RELATIONS_SERVICE_PATH
    )
    if error:
        return False, error

    message = _check_relation_create_permission(relations_action_group)
    if message:
        return False, message

    return True, None


def verify_collectionobject_search_permissions(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm the account can read/search Object records (GET /collectionobjects).

    Needed for the Object Number lookup in find_collectionobject_by_number()
    -- checked separately from verify_relation_permissions(), since an
    account could plausibly have one of these two permissions without the
    other, and both are required for the "relate to an Object record"
    feature to work. Like verify_relation_permissions(), this only runs
    when the checkbox is used, not at login for every account.

    Returns (True, None) if the account has 'R' on "collectionobjects", or
    (False, error_message) otherwise (or on a network/parsing failure).
    """
    collectionobject_action_group, error = _get_account_action_group(
        base_url, username, password, verify_ssl, COLLECTIONOBJECT_SERVICE_PATH
    )
    if error:
        return False, error

    message = _check_collectionobject_read_permission(collectionobject_action_group)
    if message:
        return False, message

    return True, None


def check_relate_to_object_permissions(base_url: str, username: str, password: str, verify_ssl: bool):
    """Confirm the account can use the "relate to an Object record" feature
    at all -- i.e. both verify_relation_permissions() and
    verify_collectionobject_search_permissions() would pass.

    This does the same two checks as calling those two functions
    separately, but shares a single /accounts/0/accountperms fetch
    between them (via _fetch_account_permission_root()), and returns
    every applicable error at once instead of stopping at the first one.
    Used both to decide whether to offer the "Relate this Media record to
    an existing Object record" checkbox on the index page at all, and by
    create() to do one combined check instead of two separate ones.

    Returns (True, []) if the account has both 'C' on "relations" and 'R'
    on "collectionobjects". Otherwise returns (False, errors), where
    errors is a list of one or two human-readable messages -- one for
    each missing permission, or a single message if the accountperms
    request itself failed (network/auth/parsing error).
    """
    root, error = _fetch_account_permission_root(base_url, username, password, verify_ssl)
    if error:
        return False, [error]

    errors = []

    relations_action_group = _action_group_for_resource(root, RELATIONS_SERVICE_PATH)
    relation_message = _check_relation_create_permission(relations_action_group)
    if relation_message:
        errors.append(relation_message)

    collectionobject_action_group = _action_group_for_resource(root, COLLECTIONOBJECT_SERVICE_PATH)
    collectionobject_message = _check_collectionobject_read_permission(collectionobject_action_group)
    if collectionobject_message:
        errors.append(collectionobject_message)

    return (not errors), errors


# --- Relating a Media record to an existing Object (CollectionObject) record ---
#
# CollectionSpace document type names, as used in Relation records'
# subjectDocumentType/objectDocumentType fields (see MediaConstants.java /
# CollectionObjectConstants.java in the CollectionSpace services source).
MEDIA_NUXEO_DOCTYPE = "Media"
COLLECTIONOBJECT_NUXEO_DOCTYPE = "CollectionObject"

COLLECTIONOBJECT_SERVICE_PATH = "collectionobjects"
RELATIONS_SERVICE_PATH = "relations"

# The predicate used for a generic, non-hierarchical link between two
# records. This is the same default CollectionSpace's own UI uses for
# "related records" associations that aren't a broader/narrower hierarchy
# (see RelationConstants.AFFECTS_TYPE / RelationshipType "affects" in the
# CollectionSpace services source).
MEDIA_TO_OBJECT_RELATIONSHIP_TYPE = "affects"


def _escape_advanced_search_value(value: str) -> str:
    """Escape a value for embedding in a single-quoted advanced-search clause."""
    return value.replace("'", "''")


def find_collectionobject_by_number(base_url: str, username: str, password: str, verify_ssl: bool, object_number: str):
    """Look up a CollectionObject record by its exact objectNumber.

    Uses CollectionSpace's generic "advanced search" query mechanism
    (the ?as= query param every resource's GET list endpoint supports --
    see NuxeoBasedResource.getList()/isGetAllRequest() in the
    CollectionSpace services source), scoped to an exact match on the
    collectionobjects_common:objectNumber field, so the match happens
    server-side rather than as a keyword/partial-text search.

    Returns (result, error):
      - On exactly one match: ({"csid": <csid>}, None).
      - Otherwise: (None, <error message>) -- covering a network/HTTP
        failure, zero matches, and more than one match (objectNumber
        isn't guaranteed unique in every tenant configuration) alike,
        since this app treats all three the same way: don't guess,
        surface it and let the user sort it out.
    """
    advanced_search = (
        f"collectionobjects_common:objectNumber = '{_escape_advanced_search_value(object_number)}'"
    )
    collectionobjects_url = f"{base_url}/{COLLECTIONOBJECT_SERVICE_PATH}"
    try:
        resp = requests.get(
            collectionobjects_url,
            params={"as": advanced_search, "pgSz": 5},
            auth=(username, password),
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return None, f"Could not reach {base_url} to look up Object record {object_number!r}: {exc}"

    if resp.status_code == 401:
        return None, "Invalid username or password for that CollectionSpace instance."
    if resp.status_code >= 400:
        return None, (
            f"Looking up Object record {object_number!r} failed "
            f"(HTTP {resp.status_code})."
        )

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        return None, f"Couldn't parse the Object record search response from CollectionSpace: {exc}"

    # The response is an <abstract-common-list> with zero or more
    # <list-item> children, each with (at least) a <csid> child -- the
    # same generic list shape every CollectionSpace search/list endpoint
    # returns (see AbstractCommonList.xsd in the services source).
    csids = []
    for element in root:
        if _local_tag(element.tag) != "list-item":
            continue
        csid_el = _find_child(element, "csid")
        if csid_el is not None and (csid_el.text or "").strip():
            csids.append(csid_el.text.strip())

    if not csids:
        return None, f"No Object record found with Object Number {object_number!r}."
    if len(csids) > 1:
        return None, (
            f"{len(csids)} Object records match Object Number {object_number!r}; "
            "please double-check the number."
        )

    return {"csid": csids[0]}, None


def create_relation(base_url: str, username: str, password: str, verify_ssl: bool,
                     subject_csid: str, subject_doctype: str,
                     object_csid: str, object_doctype: str,
                     relationship_type: str = MEDIA_TO_OBJECT_RELATIONSHIP_TYPE):
    """Relate two existing records via POST /relations.

    Only subjectCsid, objectCsid, and relationshipType are actually
    required by CollectionSpace's own validation
    (RelationValidatorHandler.handleCreate() in the services source); the
    *DocumentType fields are included here for clarity, but the server
    overwrites them anyway (and derives the URI/refName fields this app
    deliberately doesn't send) by looking up the subject and object
    records itself
    (RelationDocumentModelHandler.populateSubjectAndObjectValues()).

    Returns (True, None) on success, or (False, error_message).
    """
    relations_url = f"{base_url}/{RELATIONS_SERVICE_PATH}"
    xml_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<document name="relations">\n'
        '<ns2:relations_common xmlns:ns2="http://collectionspace.org/services/relation">\n'
        f"  <subjectCsid>{escape(subject_csid)}</subjectCsid>\n"
        f"  <subjectDocumentType>{escape(subject_doctype)}</subjectDocumentType>\n"
        f"  <relationshipType>{escape(relationship_type)}</relationshipType>\n"
        f"  <objectCsid>{escape(object_csid)}</objectCsid>\n"
        f"  <objectDocumentType>{escape(object_doctype)}</objectDocumentType>\n"
        "</ns2:relations_common>\n"
        "</document>"
    ).encode("utf-8")

    try:
        resp = requests.post(
            relations_url,
            data=xml_payload,
            headers={"Content-Type": "application/xml"},
            auth=(username, password),
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return False, f"Could not reach {base_url} to create the relation: {exc}"

    if resp.status_code not in (200, 201):
        return False, (
            f"Creating the relation failed (HTTP {resp.status_code}): "
            f"{resp.text[:500] or '(no response body)'}"
        )

    return True, None


def create_reciprocal_relations(base_url: str, username: str, password: str, verify_ssl: bool,
                                 media_csid: str, object_csid: str,
                                 relationship_type: str = MEDIA_TO_OBJECT_RELATIONSHIP_TYPE):
    """Relate a Media record and an Object record via TWO relation
    documents -- one in each direction -- rather than create_relation()'s
    single call.

    CollectionSpace itself never creates a reverse relation
    automatically -- neither the Relations service (a POST creates
    exactly one document; see RelationValidatorHandler /
    RelationDocumentModelHandler in the services source) nor the Media
    or CollectionObject document handlers, which never touch relations
    at all. But CollectionSpace's own web application does, whenever a
    user relates two records through it: unless the request is
    explicitly marked "one-way", RelateCreateUpdate.relate() (in the
    "application" repo's cspi-webui module) creates a forward relation
    and then a second, reversed one.

    That's not just a convenience -- it's load-bearing. A record's
    "related records" panel in the CollectionSpace UI only ever queries
    relations where THAT record is the subject (RecordRelated.store_get()
    passes "src", which ServicesRelationStorage.java turns into
    GET /relations?sbj=<csid> -- never with andReciprocal). So a single
    one-directional relation (Media as subject, Object as object) is a
    perfectly valid document, and will show up on the MEDIA record's
    panel, but never on the OBJECT record's -- which, for this app, is
    usually the one you're actually looking at afterwards. Creating both
    directions here is what makes the relationship visible from either
    record, matching what relating two records through CollectionSpace's
    own UI actually does.

    Returns (outcome, errors): outcome is one of "both", "media_only",
    "object_only", or "neither", telling you which direction(s) exist;
    errors is a list with one message per direction that failed (so
    it's empty only when outcome == "both"). Whichever direction(s) DID
    succeed are left in place even if the other fails -- there's no
    rollback -- so a partial result is still progress, not nothing.
    """
    media_to_object_ok, media_to_object_error = create_relation(
        base_url, username, password, verify_ssl,
        subject_csid=media_csid, subject_doctype=MEDIA_NUXEO_DOCTYPE,
        object_csid=object_csid, object_doctype=COLLECTIONOBJECT_NUXEO_DOCTYPE,
        relationship_type=relationship_type,
    )
    if not media_to_object_ok:
        media_to_object_error = f"Media → Object relation: {media_to_object_error}"

    object_to_media_ok, object_to_media_error = create_relation(
        base_url, username, password, verify_ssl,
        subject_csid=object_csid, subject_doctype=COLLECTIONOBJECT_NUXEO_DOCTYPE,
        object_csid=media_csid, object_doctype=MEDIA_NUXEO_DOCTYPE,
        relationship_type=relationship_type,
    )
    if not object_to_media_ok:
        object_to_media_error = f"Object → Media relation: {object_to_media_error}"

    errors = [e for e in (media_to_object_error, object_to_media_error) if e]

    if media_to_object_ok and object_to_media_ok:
        outcome = "both"
    elif media_to_object_ok:
        outcome = "media_only"
    elif object_to_media_ok:
        outcome = "object_only"
    else:
        outcome = "neither"

    return outcome, errors


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
    try:
        creds = load_login_secret(session["cs_secret_name"])
    except (BotoCoreError, ClientError):
        # The secret's gone or unreachable -- treat this the same as a
        # logout rather than surfacing a raw AWS error on the home page.
        session.clear()
        return redirect(url_for("login"))

    # Checked up front so the "relate to an Object record" checkbox and
    # Object Number field can be disabled -- with an explanation -- for
    # an account that doesn't have what this feature needs, rather than
    # letting the user fill them in and only finding out at submit time.
    can_relate_to_object, relate_permission_errors = check_relate_to_object_permissions(
        creds["instance_url"], creds["username"], creds["password"], creds["verify_ssl"]
    )

    return render_template_string(
        INDEX_TEMPLATE,
        username=session.get("cs_username"),
        instance_url=session.get("cs_instance_url"),
        can_relate_to_object=can_relate_to_object,
        relate_permission_errors=relate_permission_errors,
    )


@app.route("/check_object_number", methods=["GET"])
@login_required
def check_object_number():
    """AJAX endpoint behind the "Check" button next to Object Number.

    Lets the user confirm an Object record exists (and see which one)
    before clicking "Create Media record", rather than only finding out
    via a full-page error after submitting the whole form. Read-only --
    creates nothing -- and reuses the exact same
    find_collectionobject_by_number() lookup create() itself uses at
    submit time, so a "found" result here means the real submission's
    lookup will find the same thing, as long as the record and the
    account's permissions don't change in between.

    Always returns JSON with a "found" boolean. On success:
    {"found": true, "csid": "..."}. On failure (validation, permission,
    lookup, or session problem): {"found": false, "error": "..."}, with
    an appropriate HTTP status code (400/401/403/404).
    """
    try:
        creds = load_login_secret(session["cs_secret_name"])
    except (BotoCoreError, ClientError):
        # Same situation index()/create() treat as a logout -- but this
        # is an AJAX call, not a page load, so report it as JSON rather
        # than redirecting.
        session.clear()
        return jsonify(found=False, error="Your session has expired. Please log in again."), 401

    object_number = request.args.get("object_number", "").strip()
    if not object_number:
        return jsonify(found=False, error="Enter an Object Number first."), 400

    perm_ok, perm_error = verify_collectionobject_search_permissions(
        creds["instance_url"], creds["username"], creds["password"], creds["verify_ssl"]
    )
    if not perm_ok:
        return jsonify(found=False, error=perm_error), 403

    result, lookup_error = find_collectionobject_by_number(
        creds["instance_url"], creds["username"], creds["password"], creds["verify_ssl"], object_number
    )
    if lookup_error:
        return jsonify(found=False, error=lookup_error), 404

    return jsonify(found=True, csid=result["csid"])


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
    relate_to_object = request.form.get("relate_to_object") == "on"
    object_number = request.form.get("object_number", "").strip()

    errors = []
    if not title.strip():
        errors.append("Title is required.")
    if not identification_number.strip():
        errors.append("ID is required.")
    if uploaded_file is None or uploaded_file.filename == "":
        errors.append("A file to upload is required.")
    if relate_to_object and not object_number:
        errors.append("Object Number is required when relating to an existing Object record.")

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

    # If asked to relate this Media record to an existing Object record,
    # confirm the account has both permissions this feature needs --
    # 'R' on collectionobjects (to look the Object Number up) and 'C' on
    # relations (to create the link) -- then confirm the Object record
    # actually exists. All of this happens *before* creating anything, so
    # a missing permission or a bad Object Number can never leave behind
    # an orphaned Media record. Both permissions are checked (rather than
    # stopping at the first missing one) so the user sees everything
    # that needs fixing in one pass, the same way the Title/ID/file
    # checks above do.
    related_object_csid = None
    if relate_to_object:
        can_relate, permission_errors = check_relate_to_object_permissions(
            base_url, creds["username"], creds["password"], verify_ssl
        )

        if not can_relate:
            return (
                render_template_string(
                    RESULT_TEMPLATE,
                    success=False,
                    message="Please fix the following and try again:",
                    errors=permission_errors,
                    details=None,
                    username=creds["username"],
                    instance_url=base_url,
                ),
                403,
            )

        lookup_result, lookup_error = find_collectionobject_by_number(
            base_url, creds["username"], creds["password"], verify_ssl, object_number
        )
        if lookup_error:
            return (
                render_template_string(
                    RESULT_TEMPLATE,
                    success=False,
                    message="Please fix the following and try again:",
                    errors=[lookup_error],
                    details=None,
                    username=creds["username"],
                    instance_url=base_url,
                ),
                400,
            )
        related_object_csid = lookup_result["csid"]

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

    message = "Media record created and file uploaded and linked successfully."
    details = {
        "media_csid": media_csid,
        "media_record": f"{base_url}/media/{media_csid}",
        "blob_record": f"{base_url}/media/{media_csid}/blob",
        "blob_content": f"{base_url}/media/{media_csid}/blob/content",
    }

    # --- Step 3 (optional): relate the Media record to the Object record ---
    #
    # The Object record's existence was already confirmed before Step 1, so
    # the only way this fails now is a transient/permissions problem with
    # the relations service itself. Either way, the Media and Blob records
    # this app set out to create already exist -- report the relation
    # outcome alongside that success rather than hiding it behind a
    # generic failure page.
    #
    # This creates relation records in BOTH directions (Media->Object and
    # Object->Media), not just one -- see create_reciprocal_relations()'s
    # docstring. In short: CollectionSpace's own "related records" panel
    # for a given record only ever looks for relations where THAT record
    # is the subject, so a single one-directional relation is only ever
    # visible from one side. Two records aren't reliably "related" in
    # CollectionSpace's UI until both directions exist.
    warnings = None
    if related_object_csid:
        outcome, relation_errors = create_reciprocal_relations(
            base_url,
            creds["username"],
            creds["password"],
            verify_ssl,
            media_csid=media_csid,
            object_csid=related_object_csid,
        )
        if outcome == "both":
            message += f" It was also related to Object record {object_number!r}."
            details["related_object_csid"] = related_object_csid
            details["related_object_record"] = f"{base_url}/collectionobjects/{related_object_csid}"
        else:
            # Deliberately NOT folded into `message` -- a relation problem
            # here is easy to miss when it's just one more sentence under a
            # big green "Success" heading, so it gets its own visually
            # distinct (amber, not red -- the Media/Blob records genuinely
            # did succeed) block instead. See RESULT_TEMPLATE's "warnings"
            # handling.
            if outcome == "media_only":
                visibility_note = (
                    "Only the Media -> Object direction was created, so this "
                    "relation will show up on the Media record's related-records "
                    "view, but not on the Object record's."
                )
            elif outcome == "object_only":
                visibility_note = (
                    "Only the Object -> Media direction was created, so this "
                    "relation will show up on the Object record's related-records "
                    "view, but not on the Media record's."
                )
            else:
                visibility_note = "Neither direction could be created."
            warnings = [
                f"Relating this Media record to Object record {object_number!r} "
                f"wasn't fully completed. {visibility_note} " + " ".join(relation_errors)
            ]

    return render_template_string(
        RESULT_TEMPLATE,
        success=True,
        message=message,
        errors=None,
        warnings=warnings,
        details=details,
        username=creds["username"],
        instance_url=base_url,
    )


if __name__ == "__main__":
    app.run(debug=True)
