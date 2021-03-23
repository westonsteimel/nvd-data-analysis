import json
import toml
import glob
import requests
import os
import os.path

known_matches = {}
new_possible_matches = {}
already_matched = {}
SAFETY_DB_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
safety_db = json.loads(requests.get(SAFETY_DB_URL).content)
nvd_path = '/home/weston/github/westonsteimel/vuln-list-main/nvd'
package_metadata_db_files = glob.glob(f'/home/weston/github/westonsteimel/universal-package-metadata-config/pypi/*.toml')

for config in package_metadata_db_files:
    with open(config, 'r+') as f:
        t_config = toml.load(f)
        known_matches[t_config['name'].lower()] = True

for name, vulns in safety_db.items():
    if name != '$meta' and name.lower() not in known_matches:
        package = name

        for vuln in vulns:
            cve = vuln.get('cve')

            if cve:
                print(f'{name}: {cve}')
                cve_components = cve.split('-')

                if len(cve_components) != 3:
                    print(cve)
                    continue

                cve_dir = cve_components[1]
                cve_path = f'{nvd_path}/{cve_dir}/{cve}.json'

                if os.path.exists(cve_path):
                    with open(cve_path, 'r+') as cve_file:
                        cve_info = json.load(cve_file)
                        nodes = cve_info.get('configurations', {}).get('nodes', [])
                        package_info = []
                        found_exact_match = False

                        #TODO: We should try to find the best matching CPE here - for instance does the product
                        # component contain the package name, etc
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

                                    if (package.lower() in product.lower() 
                                        or package.replace('-', '_').lower() in product.lower()):
                                            pi = {
                                                'part': part,
                                                'vendor': vendor,
                                                'product': product,
                                                'target_software': target_software
                                            }
                                            m_key = f'{part}:{vendor}:{product}:{target_software}'
                                            found_exact_match = True

                                            if m_key not in already_matched:
                                                already_matched[m_key] = True
                                                package_info.append(pi)

                                if found_exact_match:
                                    break

                            if package_info:
                                new_possible_matches[package] = package_info

with open('data/pyupio/package_info.json', 'w+') as f:
    json.dump(new_possible_matches, f, indent=2)

for package, infos in new_possible_matches.items():
    os.makedirs(f'output/pypi-pyupio', exist_ok=True)
    cpe_configs = []

    for info in infos:
        cpe_config = {}

        if info.get('part') and info['part'] != 'a':
            cpe_config['part'] = info['part']
        
        cpe_config['vendor'] = info['vendor']
        cpe_config['product'] = info['product']
        
        if info.get('target_software') and info['target_software'] != '*':
            cpe_config['target_software'] = info['target_software']
            
        cpe_configs.append(cpe_config)

    package_config_entry = {
        'name': package,
        'ecosystem': 'pypi',
        'cpe_configurations': cpe_configs
    }

    toml_path = f'output/pypi-pyupio/{package}.toml'
    with open(toml_path, 'w') as f:
        toml.dump(package_config_entry, f)

