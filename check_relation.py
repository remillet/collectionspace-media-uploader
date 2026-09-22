"""
Diagnostic tool: lists CollectionSpace relations for a given record CSID,
and flags whether both directions of a relation to a specific other CSID
exist.

Directly queries GET /relations?sbj=<csid>&andReciprocal=true, so you can
confirm whether a relation record actually exists in CollectionSpace --
independent of whatever a specific CollectionSpace UI screen chooses to
display, and independent of anything the Media Uploader app itself
reports. Useful when the app says a Media record was related to an Object
record (or reports that relating it failed), and you want to check for
yourself what CollectionSpace actually has on file.

andReciprocal=true asks the Relations service to also search with the
subject and object reversed, so you'll see relations regardless of which
side of them the CSID you're searching for happens to be on. That
matters here specifically because CollectionSpace's "related records"
panel for a given record only ever shows relations where THAT record is
the subject -- so two records aren't reliably "related" in the
CollectionSpace UI (visible from both sides) unless a relation record
exists in EACH direction. This app creates both by default (see
create_reciprocal_relations() in app.py); this script's "Forward"/
"Reverse" labels below let you confirm both actually exist.

Password is entered interactively via getpass and never printed, logged,
or written anywhere.

Usage: python3 check_relation.py
"""
import getpass
import xml.etree.ElementTree as ET

import requests

instance_url = input(
    "CollectionSpace instance base URL (e.g. https://myinstance.org/cspace-services): "
).strip()
username = input("Username: ").strip()
password = getpass.getpass("Password: ")
csid = input("CSID to check relations for (e.g. a Media record's CSID): ").strip()
other_csid = input(
    "Optional: the other record's CSID, to check both directions exist "
    "between just these two (leave blank to list ALL relations for the "
    "first CSID instead): "
).strip()

resp = requests.get(
    f"{instance_url}/relations",
    params={"sbj": csid, "andReciprocal": "true"},
    auth=(username, password),
)
print("HTTP status:", resp.status_code)
if resp.status_code >= 400:
    print(resp.text[:2000])
    raise SystemExit(1)


def local(tag):
    return tag.rsplit("}", 1)[-1]


root = ET.fromstring(resp.content)
relations = []
for el in root:
    if local(el.tag) != "relation-list-item":
        continue
    relations.append({local(c.tag): (c.text or "") for c in el})

if other_csid:
    forward = any(r.get("subjectCsid") == csid and r.get("objectCsid") == other_csid for r in relations)
    reverse = any(r.get("subjectCsid") == other_csid and r.get("objectCsid") == csid for r in relations)
    print(f"  Forward ({csid} -> {other_csid}): {'found' if forward else 'MISSING'}")
    print(f"  Reverse ({other_csid} -> {csid}): {'found' if reverse else 'MISSING'}")
    if forward and reverse:
        print("  Both directions exist -- this pair should show up as related from either record's view.")
    elif forward or reverse:
        print(
            "  Only one direction exists -- this pair will show up as related from "
            "only ONE of the two records' views in CollectionSpace, not both."
        )
    else:
        print("  Neither direction exists -- these two records are not related in CollectionSpace.")
else:
    if not relations:
        print(f"  (no relations found where {csid!r} is the subject or object)")
    for fields in relations:
        direction = "forward (subject)" if fields.get("subjectCsid") == csid else "reverse (object)"
        print(
            f"  [{direction}]  csid={fields.get('csid')!r}  "
            f"subjectCsid={fields.get('subjectCsid')!r}  "
            f"predicate={fields.get('predicate')!r}  "
            f"objectCsid={fields.get('objectCsid')!r}"
        )
