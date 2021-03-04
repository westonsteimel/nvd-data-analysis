import os
import json
import gzip
import requests
import xmltodict

CPE_MATCH_URL = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
CPE_DICT_V23_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

cpe_matches = json.loads(gzip.decompress(requests.get(CPE_MATCH_URL).content))["matches"]

cpes_with_no_name = []
cpes_with_cves = {}
all_cpes = {}

for m in cpe_matches:
    cpe_uri = m.get("cpe23Uri")

    if not m.get("cpe_name"):
        cpes_with_no_name.append(cpe_uri)

    cpes_with_cves[cpe_uri] = True
    all_cpes[cpe_uri] = True

cpes_with_no_name = sorted(cpes_with_no_name)

official_cpe_list = xmltodict.parse(gzip.decompress(requests.get(CPE_DICT_V23_URL).content))['cpe-list']['cpe-item']

cpe_22_dict = {}
cpe_23_dict = {}

official_but_no_cve = []

for item in official_cpe_list:
    if item.get("@deprecated", False) == "true":
        continue

    cpe23 = item.get('cpe-23:cpe23-item')

    if cpe23:
        name = cpe23.get('@name')
        cpe_23_dict[name] = item
        all_cpes[name] = True

        if not cpes_with_cves.get(name):
            official_but_no_cve.append(name)
    else:
        name = item.get('@name')
        cpe_22_dict[name] = item

official_but_no_cve = sorted(official_but_no_cve)
cpe_prefixes = {}

for cpe in all_cpes.keys():
    components = cpe.split(':')
    prefix = ':'.join(components[3:5])

    cpe_prefixes[prefix] = True

sorted_prefixes = sorted(cpe_prefixes.keys())

os.makedirs('data/cpe/', exist_ok=True)

print(f'Match feed total: {len(cpe_matches)}')
print(f'Missing official entry: {len(cpes_with_no_name)}')
print(f'Official Entry Total: {len(official_cpe_list)}')
print(f'Official Entry without CVE: {len(official_but_no_cve)}')
print(f'Unique CPE prefixes: {len(sorted_prefixes)}')

with open('data/cpe/missing_cpe_dict_entries.json', 'w+') as f:
    json.dump(cpes_with_no_name, f, indent=2)

with open('data/cpe/official_entries_without_cve.json', 'w+') as f:
    json.dump(official_but_no_cve, f, indent=2)

with open('data/cpe/unique_prefixes.json', 'w+') as f:
    json.dump(sorted_prefixes, f, indent=2)

