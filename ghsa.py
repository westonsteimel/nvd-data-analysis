import json
import toml
import glob
import requests
import os
import os.path
import copy

current_package_metadata = {}
updated_package_metadata = {}
data_path = '/home/weston/github/westonsteimel/vuln-list-main'
severity='critical'
advisory_files = glob.glob(f'{data_path}/ghsa/**/*.json', recursive=True)
package_metadata_files = glob.glob(f'/home/weston/github/westonsteimel/package-metadata/**/*.toml')

for metadata_file in package_metadata_files:
    with open(metadata_file, 'r+') as f:
        print(metadata_file)
        metadata = toml.load(f)
        ecosystem = metadata['ecosystem'].lower()
        name = metadata['name'].lower()
        lookup_key = f'{ecosystem}:{name}'
        current_package_metadata[lookup_key] = metadata

for advisory_file in advisory_files:
    with open(advisory_file, 'r+') as f:
        print(advisory_file)
        advisory = json.load(f)

        if severity:
            if advisory.get('Severity').lower() != severity:
                continue

            package_info = advisory.get('Package')

            if not package_info:
                continue

            ecosystem = package_info['Ecosystem'].lower()

            if ecosystem == 'pip':
                ecosystem = 'pypi'

            name = package_info['Name']
            lookup_key = f'{ecosystem}:{name.lower()}'

            if lookup_key not in updated_package_metadata:
                if lookup_key in current_package_metadata:
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

            for ref in advisory.get('Advisory', {}).get('References', []):
                url = ref.get('Url')

                if url.startswith('https://nvd.nist.gov/vuln/detail/'):
                    cve = url.split('/')[-1]
                    cve_components = cve.split('-')

                    if len(cve_components) != 3:
                        print(f'CVE {cve} in file {advisory_file} had more than 3 components.')
                        continue

                    cve_dir = cve_components[1]
                    cve_path = f'{data_path}/nvd/{cve_dir}/{cve}.json'

                    if os.path.exists(cve_path):
                        with open(cve_path, 'r+') as cve_file:
                            cve_info = json.load(cve_file)
                            nodes = cve_info.get('configurations', {}).get('nodes', [])

                            for node in nodes:
                                matches = node.get('cpe_match', [])

                                for match in matches:
                                    uri = match.get('cpe23Uri')
                                    
                                    if uri:
                                        cpe_components = uri.split(':')
                                        part = cpe_components[2]
                                        vendor = cpe_components[3]
                                        product = cpe_components[4]
                                        target_software = cpe_components[10]

                                        if (part == 'o' and vendor == 'fedoraproject' and product == 'fedora') \
                                            or (part == 'o' and vendor == 'debian' and product == 'debian_linux') \
                                            or (part == 'a' and vendor == 'opensuse' and product == 'backports_sle') \
                                            or (part == 'o' and vendor == 'opensuse' and product == 'leap') \
                                            or (part == 'o' and vendor == 'canonical' and product == 'ubuntu_linux'):
                                            or (part == 'o' and vendor == 'oracle' and product == 'solaris') \
                                            or (part == 'o' and vendor == 'redhat' and product.startswith('enterprise_linux')) \
                                            or (vendor == 'redhat' and product == 'openstack' and product not in name.lower()):

                                            continue

                                        cpe_key = f'{part}:{vendor}:{product}:{target_software}'

                                        if cpe_key not in package_metadata['cpe_mapping']:
                                            cpe = {
                                                'vendor': vendor,
                                                'product': product, 
                                            }

                                            if part != 'a':
                                                cpe['part'] = part

                                            if target_software != '*':
                                                cpe['target_software'] = target_software

                                            package_metadata['cpe_mapping'][cpe_key] = cpe
                                            package_metadata['cpe_configurations'].append(cpe)

            updated_package_metadata[lookup_key] = package_metadata

#with open('output/ghsa/package_info_debug.json', 'w+') as f:
#    json.dump(updated_package_metadata, f, indent=2)

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
    outdir = f'output/all/{ecosystem}'

    if severity:
        outdir = f'output/{severity}/{ecosystem}'

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

