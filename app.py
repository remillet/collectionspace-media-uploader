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

Run:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000 in a browser.

Security notes:
    - The credentials you enter are used only to make the two API calls
      below, directly to the CollectionSpace instance URL you provide.
      They are never logged, written to disk, or sent anywhere else.
    - Only use this against a CollectionSpace instance and account you
      control and trust.
    - SSL certificate verification is ON by default. Only disable it for
      a self-hosted/sandbox instance with a self-signed certificate that
      you trust.
"""

from xml.sax.saxutils import escape

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload cap

INDEX_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CollectionSpace Media Uploader</title>
  <style>
    body { font-family: sans-serif; max-width: 560px; margin: 40px auto; padding: 0 16px; color: #1c1e21; }
    label { display: block; margin-top: 14px; font-weight: 600; }
    input[type=text], input[type=password], input[type=file] {
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
  </style>
</head>
<body>
  <h1>Create a CollectionSpace Media record</h1>
  <p>
    This creates a Media record and links an uploaded file to it as a Blob
    record, via <code>POST /media</code> followed by
    <code>PUT /media/{csid}/blob</code>.
  </p>

  <form action="/create" method="post" enctype="multipart/form-data">
    <label for="instance_url">CollectionSpace instance URL</label>
    <input type="text" id="instance_url" name="instance_url"
           placeholder="https://myinstance.collectionspace.org" required>
    <div class="hint">Base URL only &mdash; <code>/cspace-services</code> is added automatically if missing.</div>

    <label for="title">Title</label>
    <input type="text" id="title" name="title" required>

    <label for="identification_number">ID</label>
    <input type="text" id="identification_number" name="identification_number" required>

    <label for="file">Photo or document to upload</label>
    <input type="file" id="file" name="file" required>

    <label for="username">CollectionSpace username</label>
    <input type="text" id="username" name="username" autocomplete="username" required>

    <label for="password">CollectionSpace password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>

    <div class="checkbox-row">
      <input type="checkbox" id="verify_ssl" name="verify_ssl" checked>
      <label for="verify_ssl">Verify SSL certificate (uncheck only for self-signed dev/sandbox instances)</label>
    </div>

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
  </style>
</head>
<body>
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

  <a class="back" href="/">&larr; Create another</a>
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


@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_TEMPLATE)


@app.route("/create", methods=["POST"])
def create():
    instance_url = request.form.get("instance_url", "")
    title = request.form.get("title", "")
    identification_number = request.form.get("identification_number", "")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    verify_ssl = request.form.get("verify_ssl") == "on"
    uploaded_file = request.files.get("file")

    errors = []
    if not instance_url.strip():
        errors.append("CollectionSpace instance URL is required.")
    if not title.strip():
        errors.append("Title is required.")
    if not identification_number.strip():
        errors.append("ID is required.")
    if not username.strip() or not password:
        errors.append("Username and password are required.")
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
            ),
            400,
        )

    base_url = normalize_base_url(instance_url)
    auth = (username, password)

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
            ),
            502,
        )

    if blob_resp.status_code != 200:
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
    )


if __name__ == "__main__":
    app.run(debug=True)
