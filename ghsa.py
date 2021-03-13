import json
import toml
import glob
import requests
import os
import os.path

found = {}
data_path = '/home/weston/github/westonsteimel/vuln-list-main'

files = glob.glob(f'{data_path}/ghsa/**/*.json', recursive=True)

for f in files:
    components = f.replace(f'{data_path}/', '').split('/')
    ecosystem = components[1]
    package = '/'.join(components[2:-1])

    if ecosystem not in found:
        found[ecosystem] = {}

    if package not in found[ecosystem]:
        with open(f, 'r+') as advisory_file:
            ghsa = json.load(advisory_file)
            
            for ref in ghsa.get('Advisory', {}).get('References', []):
                if package in found[ecosystem]:
                    break

                url = ref.get('Url')

                if url.startswith('https://nvd.nist.gov/vuln/detail/'):
                    cve = url.split('/')[-1]
                    cve_components = cve.split('-')

                    if len(cve_components) != 3:
                        print(cve)
                        continue

                    cve_dir = cve_components[1]
                    cve_path = f'{data_path}/nvd/{cve_dir}/{cve}.json'

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

                                        if product.lower() == package.lower():
                                            package_info = [{
                                                'part': part,
                                                'vendor': vendor,
                                                'product': product,
                                                'target_software': target_software
                                            }]
                                            found_exact_match = True
                                            break
                                        elif vendor not in ['fedoraproject', 'debian', 'opensuse', 'redhat']:
                                            package_info.append({
                                                'part': part,
                                                'vendor': vendor,
                                                'product': product,
                                                'target_software': target_software
                                            })
                                
                                if found_exact_match:
                                    break

                            if package_info:
                                found[ecosystem][package] = package_info

# There are definitely extra CPE's for several microsoft ones 
# (.net_core, .net_framework, asp.net_core, and usually only one applies to the package)
# so definitely review any of those
if 'nuget' in found:
    for k, v in found['nuget'].items():
        for i in v:
            if i.get('vendor')=='microsoft':
                print(f'{k}: {v}')
                break

with open('data/ghsa/package_info.json', 'w+') as f:
    json.dump(found, f, indent=2)

for ecosystem, package_dict in found.items():
    if ecosystem == 'pip':
        ecosystem = 'pypi'

    os.makedirs(f'output/{ecosystem}', exist_ok=True)

    for name, infos in package_dict.items():
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
            'name': name,
            'ecosystem': ecosystem,
            'cpe_configurations': cpe_configs
        }

        filename = os.path.basename(name)

        if name == filename:
            toml_path = f'output/{ecosystem}/{filename}.toml'
        else:
            directory = os.path.dirname(name)
            toml_path = f'output/{ecosystem}/{directory}/{filename}.toml'

            os.makedirs(f'output/{ecosystem}/{directory}', exist_ok=True)

        with open(toml_path, 'w') as f:
            toml.dump(package_config_entry, f)

