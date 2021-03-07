import os
import json
import gzip
import requests
import xmltodict

CPE_MATCH_URL = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
CPE_DICT_V23_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

cpe_matches = json.loads(gzip.decompress(requests.get(CPE_MATCH_URL).content))["matches"]

cpes_with_no_official_entry = []
match_feed_cpes = {}
all_cpes = {}

for m in cpe_matches:
    cpe_uri = m.get("cpe23Uri")

    if not m.get("cpe_name"):
        cpes_with_no_official_entry.append(cpe_uri)

    for cpe in m.get("cpe_name", []):
        uri = m.get("cpe23Uri")

        if uri:
            all_cpes[uri] = True
            match_feed_cpes[uri] = True

    all_cpes[cpe_uri] = True
    match_feed_cpes[cpe_uri] = True

cpes_with_no_official_entry = sorted(cpes_with_no_official_entry)

official_cpe_list = xmltodict.parse(gzip.decompress(requests.get(CPE_DICT_V23_URL).content))['cpe-list']['cpe-item']

cpe_23_dict = {}

for item in official_cpe_list:
    deprecated = item.get("@deprecated", False) == "true"
    cpe23 = item.get('cpe-23:cpe23-item')

    if cpe23:
        name = cpe23.get('@name')
        
        if not deprecated:
            title = item.get('title', {})
            
            if isinstance(title, list):
                for t in title:
                    if t.get('@xml:lang') == 'en-US':
                        title = t.get('#text')
            
            if isinstance(title, list):
                title = None

            references = item.get('references', {}).get('reference', [])
            dict_entry = {
                'title': title,
                'references': {},
            }

            if isinstance(references, dict):
                references = [references]

            for ref in references:
                dict_entry['references'][ref.get('#text')] = ref.get('@href')

            cpe_23_dict[name] = dict_entry
            all_cpes[name] = True
        else:
            if name in all_cpes:
                del all_cpes[name]

cpe_prefixes = {}

for cpe in all_cpes.keys():
    components = cpe.split(':')
    prefix = ':'.join(components[3:5])

    cpe_prefixes[prefix] = True

sorted_prefixes = sorted(cpe_prefixes.keys())
sorted_all = sorted(all_cpes.keys())

os.makedirs('data/cpe/', exist_ok=True)

print(f'CPE match feed total: {len(match_feed_cpes)}')
print(f'Official Entries Total: {len(cpe_23_dict)}')
print(f'Missing official entry: {len(cpes_with_no_official_entry)}')
print(f'All: {len(sorted_all)}')
print(f'Unique CPE prefixes: {len(sorted_prefixes)}')

with open('data/cpe/cpes_with_no_official_entry.json', 'w+') as f:
    json.dump(cpes_with_no_official_entry, f, indent=2)

with open('data/cpe/all_cpes.json', 'w+') as f:
    json.dump(sorted_all, f, indent=2)

with open('data/cpe/unique_prefixes.json', 'w+') as f:
    json.dump(sorted_prefixes, f, indent=2)

with open('data/cpe/official_dictionary.json', 'w+') as f:
    json.dump(cpe_23_dict, f, indent=2)

