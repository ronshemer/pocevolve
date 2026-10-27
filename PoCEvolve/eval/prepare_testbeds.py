#!/usr/bin/env python3
"""Install vulnerable benchmark packages into local PoCEvolve/testbed directories."""
import argparse
import json
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
g=p.add_mutually_exclusive_group(); g.add_argument('--cve'); g.add_argument('--dataset',type=Path)
a=p.parse_args()
src=a.dataset or ROOT/'datasets/SecBench.js.PoCGen.vfc.190'
ids=[x.strip() for x in src.read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
rows=json.loads((ROOT/'secbenchjs/vfcs.filtered.json').read_text())
byid={str(r.get('testbed_dir','')).replace(':','_'):r for r in rows}
if a.cve:
 want=a.cve.replace(':','_'); r=next((r for r in rows if want in [str(x).replace(':','_') for x in r.get('ids',[]) + [r.get('testbed_dir','')]]),None)
 if not r: p.error(f'No benchmark record for {a.cve}')
 canonical=r.get('testbed_dir','').replace(':','_'); ids=[i for i in ids if i.replace(':','_')==canonical]
 if not ids: p.error(f'{a.cve} is not present in {src}')
for ident in ids:
 r=byid.get(ident.replace(':','_'))
 if not r or not r.get('vulnerable_package') or not r.get('vulnerable_version'): p.error(f'Missing npm metadata for {ident}')
 target=ROOT/'eval'/'testbeds'/ident.replace(':','_'); module=target/'node_modules'/r['vulnerable_package']
 if module.is_dir(): print(f'[ready] {ident}'); continue
 target.mkdir(parents=True,exist_ok=True)
 print(f"[npm] {ident}: {r['vulnerable_package']}@{r['vulnerable_version']}",flush=True)
 subprocess.run(['npm','install','--prefix',str(target),'--ignore-scripts',f"{r['vulnerable_package']}@{r['vulnerable_version']}"],check=True)
