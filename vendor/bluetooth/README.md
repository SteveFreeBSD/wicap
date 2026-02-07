Bluetooth Company IDs
=====================

This directory contains the Bluetooth SIG Company Identifier list used for
vendor enrichment in WICAP.

Canonical docs live under `docs/` only. Do not add roadmaps or reports here.
Start here for project-wide docs: `docs/INDEX.md`

Source
------
The list is derived from the official Bluetooth SIG assigned numbers:

https://bitbucket.org/bluetooth-SIG/public/raw/HEAD/assigned_numbers/company_identifiers/company_identifiers.yaml

WICAP consumes the JSON form at `vendor/bluetooth/company_ids.json`.

Update Procedure
----------------
Run the helper snippet below to refresh from the SIG source and re-sort the
keys for stable diffs:

```bash
python3 - <<'PY'
import json
import urllib.request

url = 'https://bitbucket.org/bluetooth-SIG/public/raw/HEAD/assigned_numbers/company_identifiers/company_identifiers.yaml'
with urllib.request.urlopen(url) as f:
    data = f.read().decode('utf-8', errors='replace')

mapping = {}
current_value = None
for raw_line in data.splitlines():
    line = raw_line.strip()
    if line.startswith('- value:'):
        token = line.split(':', 1)[1].strip()
        if token.lower().startswith('0x'):
            token = token[2:]
        current_value = token.upper().zfill(4)
    elif line.startswith('name:') and current_value:
        name = line.split(':', 1)[1].strip().strip('"').strip("'")
        mapping[current_value] = name
        current_value = None

ordered = {k: mapping[k] for k in sorted(mapping.keys())}
with open('vendor/bluetooth/company_ids.json', 'w', encoding='utf-8') as f:
    json.dump(ordered, f, indent=2, ensure_ascii=True)
print('entries', len(ordered))
PY
```
