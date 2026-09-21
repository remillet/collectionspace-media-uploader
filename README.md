# CollectionSpace Media Uploader

A small Flask web app that creates a CollectionSpace **Media** record and
links an uploaded photo/document to it as a **Blob** record.

It performs the two-call sequence documented in the CollectionSpace
Technical Documentation ([Media Service REST APIs](https://collectionspace.atlassian.net/wiki/spaces/cstd/pages/3581444097/Media+Service+REST+APIs)),
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

## Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Using the form

- **CollectionSpace instance URL** &mdash; the base URL of your instance, e.g.
  `https://myinstance.collectionspace.org`. `/cspace-services` is appended
  automatically if you leave it off.
- **Title** / **ID** &mdash; used to populate the new Media record's `title` and
  `identificationNumber` fields.
- **Photo or document to upload** &mdash; the file that becomes the linked Blob
  record's content.
- **Username / password** &mdash; your CollectionSpace account credentials, sent
  as HTTP Basic Auth directly to the instance URL above.
- **Verify SSL certificate** &mdash; leave checked unless you're pointing at a
  self-hosted/sandbox instance with a self-signed certificate you trust.

On success, the result page shows the new Media record's CSID and direct
links to the Media record, the Blob record, and the raw file content.

## Security notes

- Your credentials are used only to make the two API calls above, over
  HTTPS, directly to the instance URL you enter. This app does not log,
  store, or forward them anywhere else.
- Nothing is persisted between requests &mdash; each submission is a fresh,
  in-memory round trip.
- Only run this against a CollectionSpace instance and account you
  control and trust. This app is intended for local/personal use; it
  is not hardened for exposure on a public network (no rate limiting,
  no CSRF protection beyond Flask's defaults, debug mode is on).
