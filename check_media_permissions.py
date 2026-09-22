"""
Diagnostic tool: prints an account's CollectionSpace Media permissions.

Prints the resourceName/actionGroup entries from a CollectionSpace
account's GET /accounts/0/accountperms response that mention "media" or
"blob" -- the same data app.py's verify_media_permissions() checks, but
shown raw instead of turned into a pass/fail decision. Useful when login
is rejected for missing Media permissions, or you just want to see what
an account can do before handing it to someone.

Only the "media" resource's permissions matter to the uploader app; a
separate "Blob" service permission line elsewhere in CollectionSpace's
admin UI is not checked. See the README's "Checking an account's
permissions" section for why.

Password is entered interactively via getpass and never printed,
logged, or written anywhere.

Usage: python3 check_media_permissions.py
"""
import getpass
import xml.etree.ElementTree as ET

import requests

instance_url = input("CollectionSpace instance base URL (e.g. https://myinstance.org/cspace-services): ").strip()
username = input("Username: ").strip()
password = getpass.getpass("Password: ")

resp = requests.get(f"{instance_url}/accounts/0/accountperms", auth=(username, password))
print("HTTP status:", resp.status_code)

def local(tag):
    return tag.rsplit("}", 1)[-1]

root = ET.fromstring(resp.content)
found = False
for el in root.iter():
    if local(el.tag) != "permission":
        continue
    resource_name = next((c.text for c in el if local(c.tag) == "resourceName"), None)
    action_group = next((c.text for c in el if local(c.tag) == "actionGroup"), None)
    if resource_name and ("media" in resource_name.lower() or "blob" in resource_name.lower()):
        print(f"  resourceName={resource_name!r}  actionGroup={action_group!r}")
        found = True
if not found:
    print("  (no permission entries matched 'media' or 'blob')")
