import json
import toml
import glob
import requests
import os
import os.path
import copy
import re
import shutil
import zipfile

current_package_metadata = {}
updated_package_metadata = {}
input_path = './input'
osv_files = glob.glob(f'{input_path}/**/*.json', recursive=True)
package_metadata_files = glob.glob(f'./package-metadata/**/*.toml', recursive=True)
update_existing = False
include_pysec = False

osv_ecosystems = [
    #"Go",
    #"Maven",
    #"NuGet",
    #"Packagist",
    #"Pub",
    #"Hackage",
    #"Hex",
    "PyPI",
    #"RubyGems",
    #"crates.io",
    #"npm",
    #"SwiftURL",
    #"CRAN",
    #"Bitnami",
    #"Android",
]

ignored_vendor_products = {
    "opensuse:backports_sle",
    "fedoraproject:extra_packages_for_enterprise_linux",
    "redhat:software_collections",
    "redhat:satellite",
    "redhat:ansible_automation_platform",
}   

ignored_cves = {
    "CVE-2022-24719", # The request-util package here seems unrelated to the vuln.  It appears there may be a mistake in the PYSEC entry
}

def normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ["alpm", "apk", "bitbucket", "bitnami", "cargo", "composer", "deb", "gem", "github", "golang", "hex", "npm", "pub"]:
        return name.lower()
    
    return name

def download_latest_input():
    if os.path.exists(input_path):
        shutil.rmtree(input_path)

    for e in osv_ecosystems:
        path = os.path.join(input_path, e)
        os.makedirs(path, exist_ok=True)
        r = requests.get(f"https://osv-vulnerabilities.storage.googleapis.com/{e}/all.zip", stream=True)
        zip_path = os.path.join(path, "all.zip")
        with open(os.path.join(path, "all.zip"), 'wb') as fd:
            for chunk in r.iter_content(chunk_size=262100000):
                fd.write(chunk)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(path)

        os.remove(zip_path)

#download_latest_input()

for metadata_file in package_metadata_files:
    with open(metadata_file, 'r+') as f:
        #print(metadata_file)
        metadata = toml.load(f)
        ecosystem = metadata['ecosystem'].lower()
        name = normalize_package_name(ecosystem, metadata['name'])
        lookup_key = f'{ecosystem}:{name}'
        current_package_metadata[lookup_key] = metadata

for osv in osv_files:
    with open(osv, 'r+') as f:
        advisory = json.load(f)
        cve_id = None
        id = advisory["id"]
        if id.startswith("CVE-"):
            cve_id = id

        if id.startswith("PYSEC-") and not include_pysec:
            continue

        if not cve_id:
            for alias in advisory.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias

        if not cve_id:
            continue

        if cve_id in ignored_cves:
            continue

        cve_year = cve_id.split("-")[1]
        cve_path = os.path.join("./national-vulnerability-database/data", cve_year, f"{cve_id}.json")
        if not os.path.exists(cve_path):
            print(f'No CVE file found for {cve_id}')
            continue

        cpes = {}

        with open(cve_path, 'r+') as cve_file:
            cve_data = json.load(cve_file)
            cpe_configurations = cve_data.get("cve", {}).get("configurations", [])

            for c in cpe_configurations:
                for n in c.get("nodes", []):
                    for m in n.get("cpeMatch", []):
                        vulnerable = m.get("vulnerable", False)

                        if not vulnerable:
                            continue

                        criteria = m.get("criteria")

                        if not criteria.startswith("cpe:2.3:a:"):
                            continue

                        cpe_components = criteria.split(":")
                        vendor = cpe_components[3]
                        product = cpe_components[4]
                        target_software = cpe_components[-3]
                        key = f"a:{vendor}:{product}:{target_software}"

                        if f"{vendor}:{product}" in ignored_vendor_products:
                            continue

                        cpes[key] = {
                            "vendor": vendor,
                            "product": product,
                        }

                        if target_software not in {"*", "-"}:
                            cpes[key]["target_software"] = target_software

        for affected in advisory.get("affected", []):
            purl: str = affected.get("package", {}).get("purl") 

            if not purl:
                continue

            components = purl.split("/")
            ecosystem: str = components[0].removeprefix("pkg:")
            name: str = normalize_package_name(ecosystem, "/".join(components[1:]))
            lookup_key = f'{ecosystem}:{name}'

            if lookup_key not in updated_package_metadata:
                if lookup_key in current_package_metadata:
                    if not update_existing:
                        continue

                    package_metadata = copy.deepcopy(current_package_metadata[lookup_key])
                    assert package_metadata == current_package_metadata[lookup_key]

                    if 'cpe_configurations' not in package_metadata:
                        package_metadata['cpe_configurations'] = [] 
                else:
                    package_metadata = {
                        'name': name,
                        'ecosystem': ecosystem,
                        'cpe_configurations': []
                    }

                package_metadata['cpe_mapping'] = {}
            else:
                package_metadata = updated_package_metadata[lookup_key]

            for cpe_config in package_metadata.get('cpe_configurations', []):
                part = cpe_config.get('part', 'a')
                vendor = cpe_config.get('vendor')
                product = cpe_config.get('product')
                target_software = cpe_config.get('target_software', '*')
                cpe_key = f'{part}:{vendor}:{product}:{target_software}'
                package_metadata['cpe_mapping'][cpe_key] = cpe_config

            for cpe_key, cpe in cpes.items():
                if cpe_key not in package_metadata['cpe_mapping']:
                    package_metadata['cpe_mapping'][cpe_key] = cpe
                    package_metadata['cpe_configurations'].append(cpe)

            updated_package_metadata[lookup_key] = package_metadata

updates = []

for lookup_key, package_metadata in updated_package_metadata.items():
    del package_metadata['cpe_mapping']

    if lookup_key in current_package_metadata:
        if package_metadata != current_package_metadata[lookup_key]:
            updates.append(package_metadata)
    elif len(package_metadata['cpe_configurations']) > 0:
        updates.append(package_metadata)

for package_metadata in updates:
    ecosystem = package_metadata['ecosystem']
    name = package_metadata['name']
    outdir = f'./package-metadata/{ecosystem}'

    os.makedirs(outdir, exist_ok=True)

    filename = os.path.basename(name)

    if name == filename:
        toml_path = f'{outdir}/{filename}.toml'
    else:
        directory = os.path.dirname(name)
        toml_path = f'{outdir}/{directory}/{filename}.toml'

        os.makedirs(f'{outdir}/{directory}', exist_ok=True)

    with open(toml_path, 'w') as f:
        toml.dump(package_metadata, f)

