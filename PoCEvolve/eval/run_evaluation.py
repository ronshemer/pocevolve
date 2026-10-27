#!/usr/bin/env python3
"""Run direct LLM generation for one SecBench ID or the full dataset."""
import argparse, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
p=argparse.ArgumentParser(description=__doc__)
g=p.add_mutually_exclusive_group(); g.add_argument('--cve'); g.add_argument('--dataset',type=Path)
p.add_argument('--run-gepa',action='store_true'); p.add_argument('--gepa-iterations',type=int,default=5); p.add_argument('--generation-attempts',type=int,default=3); p.add_argument('--output-dir',type=Path); p.add_argument('--no-static-analysis',action='store_true',help='Disable entry-point and target-method context')
p.add_argument('--resume-dir',type=Path,help='Resume an interrupted run from its results directory')
a=p.parse_args()
if a.generation_attempts<1: p.error('--generation-attempts must be positive')
if a.resume_dir and a.output_dir: p.error('--resume-dir and --output-dir cannot be used together')
if a.resume_dir and a.cve: p.error('--resume-dir resumes the saved dataset; do not combine it with --cve')
if a.resume_dir:
    out=a.resume_dir.expanduser().resolve()
    if not out.is_dir(): p.error(f'resume directory does not exist: {out}')
    saved_dataset=out/'dataset.txt'
    if not saved_dataset.is_file(): p.error(f'resume directory has no dataset.txt: {out}')
    src=a.dataset or saved_dataset
else:
    src=a.dataset or ROOT/'datasets/SecBench.js.PoCGen.vfc.190'
if not src.is_file(): p.error(f'dataset not found: {src}')
ids=[x.strip() for x in src.read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
if a.cve:
 want=a.cve.strip().replace(':','_'); found=next((x for x in ids if x.replace(':','_')==want),None)
 if not found:
  records=json.loads((ROOT/'secbenchjs/vfcs.filtered.json').read_text()); rec=next((r for r in records if want in [str(i).replace(':','_') for i in (r.get('ids',[])+[r.get('testbed_dir','')])]),None); can=rec.get('testbed_dir','') if rec else ''; found=next((x for x in ids if can and x.replace(':','_')==can.replace(':','_')),None)
 if not found: p.error(f'{a.cve!r} not found in {src}')
 ids=[found]
if not ids: p.error(f'dataset is empty: {src}')
if a.resume_dir:
    saved_ids=[x.strip() for x in (out/'dataset.txt').read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
    normalize=lambda values:[x.replace(':','_') for x in values]
    if normalize(ids)!=normalize(saved_ids): p.error(f'dataset does not match the saved run in {out}; resume requires the same IDs in the same order')
else:
    out=a.output_dir.expanduser().resolve() if a.output_dir else ROOT/'eval/results'/datetime.now(timezone.utc).strftime('direct_%Y%m%d_%H%M%S')
    if out.exists() and any(out.iterdir()): p.error(f'output directory is not empty: {out}; use --resume-dir to continue it')
    out.mkdir(parents=True,exist_ok=True)
    (out/'dataset.txt').write_text('\n'.join(ids)+'\n')
idfile=out/'dataset.txt'
print(f'Output directory: {out}',flush=True)
env=os.environ.copy(); env.update(DATASET=str(idfile),RUN_OUTPUT_DIR=str(out),SKIP_GEPA='0' if a.run_gepa else '1',GEPA_ITERATIONS=str(a.gepa_iterations),MAX_GENERATION_ATTEMPTS=str(a.generation_attempts),USE_STATIC_ANALYSIS='0' if a.no_static_analysis else '1',PYTHONUNBUFFERED='1')
from src.config import MODEL_NAME, API_BASE
print(f'Model={MODEL_NAME} API={API_BASE} IDs={len(ids)} GEPA={a.run_gepa} attempts={a.generation_attempts} static_analysis={not a.no_static_analysis}',flush=True)
for mod in ('src.analyzer','src.generator'): subprocess.run([sys.executable,'-B','-m',mod],cwd=ROOT,env=env,check=True)
if a.run_gepa: subprocess.run([sys.executable,'-B','-m','src.evolver_llm'],cwd=ROOT,env=env,check=True)
rows=[json.loads(s) for s in (out/f'vfcs.generated.{idfile.name}.jsonl').read_text().splitlines() if s.strip()]
passed=sum(any('pass 1' in r.get('stdout','') for r in (q.get('console_log') or [])) for row in rows for q in row.get('generated_exploits',[]))
summary={'model':MODEL_NAME,'ids':ids,'gepa_enabled':a.run_gepa,'static_analysis_enabled':not a.no_static_analysis,'generation_attempts':a.generation_attempts,'passed':passed,'total':len(rows),'success_rate':passed/len(rows) if rows else 0}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(f"Initial generation: {passed}/{len(rows)} ({summary['success_rate']:.1%}); results: {out}")
