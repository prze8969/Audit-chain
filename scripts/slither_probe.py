import json
import os
import subprocess
import sys
from pathlib import Path

sol_path = sys.argv[1]
tmp_file = Path('slither_out_tmp.json')
if tmp_file.exists():
    tmp_file.unlink()

# Ensure .venv Scripts and solc artifacts are in PATH
venv_scripts = str(Path('.venv/Scripts').resolve())
solc_dir = str(Path.home() / '.solc-select' / 'artifacts' / 'solc-0.8.19')
env = os.environ.copy()
env['PATH'] = f'{venv_scripts};{solc_dir};' + env.get('PATH', '')

cmd = [sys.executable, '-m', 'slither', sol_path, '--json', str(tmp_file)]
subprocess.run(cmd, env=env, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if not tmp_file.exists():
    print(f'Error: {tmp_file} not created')
    sys.exit(1)

data = json.loads(tmp_file.read_text(encoding='utf-8'))
tmp_file.unlink()

results = data.get('results', {}).get('detectors', [])
for r in results:
    check = r.get('check')
    impact = r.get('impact')
    confidence = r.get('confidence')
    elems_desc = []
    for elem in r.get('elements', []):
        elem_type = elem.get('type')
        elem_name = elem.get('name')
        type_spec = elem.get('type_specific_fields', {})
        parent = type_spec.get('parent', {}) if type_spec else {}
        parent_name = parent.get('name') if parent else None
        sig = type_spec.get('signature') if type_spec else None
        elems_desc.append(f'{elem_type}:{elem_name}(parent={parent_name}, sig={sig})')
    print(f'{check} | {impact} | {confidence} | {", ".join(elems_desc)}')
