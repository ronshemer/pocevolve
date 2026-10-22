import json
import logging
import os
import subprocess
import time
from pathlib import Path
from tqdm import tqdm

from src.utils import load_json, extract_js_triple_backticks, _strip_static_analysis
from src.llm import call_llm
from src.prompts import (
    EXPLOIT_GENERATE_LLM_USER_PROMPT,
    EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT
)
from src.config import CWE_MAP, DATASET_LIST
from src.verify import run_verifier

logger = logging.getLogger(__name__)


def _static_analysis_enabled() -> bool:
    return os.environ.get("USE_STATIC_ANALYSIS", "").strip().lower() in {"1", "true", "yes", "on"}


def _format_static_analysis_context(data: dict, *, enabled: bool | None = None) -> str:
    """Run static analysis for this datapoint and format prompt context."""
    if enabled is None:
        enabled = _static_analysis_enabled()
    if not enabled:
        return ""

    testbed_dir = data.get("testbed_dir", "")
    cve_id = testbed_dir or data.get("id", "")
    if not cve_id:
        return "Static analysis results are unavailable: no CVE or testbed identifier was provided."

    try:
        from src.graph_analysis.testbed_manager import ensure_git_testbed
        from src.graph_analysis.vfc_loader import get_diff
        from src.graph_analysis import analyze_cve

        package_root = ensure_git_testbed(cve_id)
        diff_text = get_diff(
            testbed_dir=testbed_dir or None,
            cve_id=cve_id,
            fix_commit_url=data.get("vulnerability_fix_commit") or None,
        )
        result = analyze_cve(
            cve_id=cve_id,
            package_root=package_root,
            diff_text=diff_text or "",
            testbed_dir=testbed_dir or cve_id,
        )
        source_context = _extract_referenced_method_sources(package_root, result)
    except Exception as exc:
        tqdm.write(f"  [WARN] Static analysis unavailable for {cve_id}: {exc}")
        return "Static analysis results are unavailable for this CVE."

    sections = []
    if result.entry_points:
        sections.append("Entry points:")
        for entry_point in result.entry_points:
            if isinstance(entry_point, dict):
                file_path = entry_point.get("file_path", "")
                methods = entry_point.get("exported_methods")
                description = file_path
                if methods is not None:
                    description += f" (exported methods: {', '.join(methods) if methods else 'none identified'})"
                sections.append(f"- {description}")
            else:
                sections.append(f"- {entry_point}")
    else:
        sections.append("Entry points: none identified.")

    if result.target_methods:
        sections.append("Target methods affected by the fix:")
        for method in result.target_methods:
            file_path = method.get("file_path", "")
            method_name = method.get("method_name", "")
            line_numbers = method.get("deleted_lines") or method.get("added_line_anchors") or []
            change_type = method.get("change_type", "unknown")
            details = f"{file_path}#{method_name} ({change_type} change"
            if line_numbers:
                details += f", vulnerable-source lines: {', '.join(map(str, line_numbers))}"
            symbols = method.get("diff_symbols") or []
            if symbols:
                details += f", diff symbols: {', '.join(symbols)}"
            details += ")"
            sections.append(f"- {details}")
    else:
        sections.append("Target methods affected by the fix: none identified.")

    sections.append("Referenced method source code (from the vulnerable checkout):")
    sections.extend(source_context)

    sections.append(
        "Use these results as navigation hints: inspect the listed exported API and "
        "affected methods when choosing how to trigger the vulnerability."
    )
    return "\n".join(sections)


def _extract_referenced_method_sources(package_root: Path, result) -> list[str]:
    """Extract referenced methods with one AST-indexing process per package."""
    requests: list[tuple[str, str, int | None]] = []
    for entry_point in result.entry_points:
        if not isinstance(entry_point, dict):
            continue
        file_path = entry_point.get("file_path")
        if not file_path:
            continue
        methods = entry_point.get("exported_methods")
        if methods:
            requests.extend((file_path, str(method), None) for method in methods)
        else:
            # Preserve useful context for entry files when export extraction
            # cannot identify a method or the module exports only a value.
            requests.append((file_path, "<entry file>", None))

    for method in result.target_methods:
        file_path = method.get("file_path")
        if not file_path:
            continue
        lines = method.get("deleted_lines") or method.get("added_line_anchors") or []
        requests.append((file_path, str(method.get("method_name") or "<target method>"), min(lines) if lines else None))

    unique_requests = []
    seen = set()
    for request in requests:
        if request not in seen:
            seen.add(request)
            unique_requests.append(request)

    if not unique_requests:
        return ["- No referenced methods were identified by static analysis."]

    root = package_root.resolve()
    files = []
    for path in _iter_package_source_files(root):
        try:
            files.append(path.resolve().relative_to(root).as_posix())
        except ValueError:
            continue

    extracted = _extract_functions_from_package(root, files, unique_requests)
    snippets = []
    for request, found in zip(unique_requests, extracted):
        relative_path, method_name, _line_number = request
        if found:
            snippets.append(
                f"\n### {found['file_path']} — {found['signature']}\n"
                f"```javascript\n{found['code']}\n```"
            )
        elif method_name == "<entry file>":
            try:
                source = (root / relative_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            excerpt = "\n".join(source.splitlines()[:300])
            snippets.append(
                f"\n### {relative_path} — entry file (first 300 lines; method extraction unavailable)\n"
                f"```javascript\n{excerpt}\n```"
            )

    return snippets or ["- No referenced method bodies could be extracted from the vulnerable source checkout."]


def _iter_package_source_files(package_root: Path):
    excluded = {".git", "node_modules", "test", "tests", "coverage", "dist", "build", "vendor"}
    extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    for root, dirs, files in os.walk(package_root):
        dirs[:] = [name for name in dirs if name not in excluded and not name.startswith(".")]
        for name in files:
            path = Path(root) / name
            if path.suffix.lower() in extensions:
                yield path


def _extract_functions_from_package(
    package_root: Path,
    files: list[str],
    requests: list[tuple[str, str, int | None]],
) -> list[dict | None]:
    """Parse each package file once, then resolve all requested method snippets."""
    script = r'''const fs = require('fs');
const espree = require('espree');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const indexed = [];
function keyName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal') return String(node.value);
  return null;
}
for (const file of input.files) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (_) { continue; }
  let ast;
  try { ast = espree.parse(text, { ecmaVersion: 'latest', sourceType: 'module', loc: true, range: true, allowHashBang: true }); }
  catch (_) { try { ast = espree.parse(text, { ecmaVersion: 'latest', sourceType: 'script', loc: true, range: true, allowHashBang: true }); } catch (_) { continue; } }
  const methods = [];
  function add(node, name) {
    if (!node || !node.range || !node.loc) return;
    methods.push({
      name: name || '', startLine: node.loc.start.line, endLine: node.loc.end.line,
      span: node.range[1] - node.range[0], code: text.slice(node.range[0], node.range[1]),
    });
  }
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    switch (node.type) {
      case 'FunctionDeclaration': add(node, node.id && node.id.name); break;
      case 'MethodDefinition': add(node, keyName(node.key)); break;
      case 'Property':
        if (node.method) add(node, keyName(node.key));
        else if (node.value && ['FunctionExpression','ArrowFunctionExpression'].includes(node.value.type)) add(node.value, keyName(node.key));
        break;
      case 'VariableDeclarator':
        if (node.init && ['FunctionExpression','ArrowFunctionExpression'].includes(node.init.type)) add(node.init, keyName(node.id));
        break;
      case 'AssignmentExpression':
        if (node.right && ['FunctionExpression','ArrowFunctionExpression'].includes(node.right.type)) {
          const left = node.left;
          add(node.right, left.type === 'Identifier' ? left.name : left.type === 'MemberExpression' ? keyName(left.property) : null);
        }
        break;
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'loc' || key === 'range') continue;
      if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === 'object') walk(value);
    }
  }
  walk(ast);
  indexed.push({ file: file.slice(input.root.length + 1), methods });
}
const result = input.requests.map(([requestedFile, name, line]) => {
  let candidates = [];
  if (line !== null) {
    const source = indexed.find(entry => entry.file === requestedFile);
    if (source) candidates = source.methods.filter(item => item.startLine <= line && line <= item.endLine);
  } else if (name !== '<entry file>') {
    const local = indexed.find(entry => entry.file === requestedFile);
    if (local) candidates = local.methods.filter(item => item.name === name);
    if (!candidates.length) {
      for (const entry of indexed) {
        candidates = entry.methods.filter(item => item.name === name);
        if (candidates.length) break;
      }
    }
  }
  if (!candidates.length) return null;
  candidates.sort((a,b) => a.span - b.span);
  const best = candidates[0];
  return { file_path: (indexed.find(entry => entry.file === requestedFile)?.methods.includes(best) ? requestedFile : indexed.find(entry => entry.methods.includes(best))?.file) || requestedFile,
    signature: best.name || name, code: best.code };
});
process.stdout.write(JSON.stringify(result));
'''
    try:
        proc = subprocess.run(
            ["node", "-e", script],
            input=json.dumps({
                "root": str(package_root),
                "files": [str(package_root / path) for path in files],
                "requests": requests,
            }),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            logger.warning("Source AST extraction failed for %s: %s", package_root, proc.stderr.strip())
            return [None] * len(requests)
        results = json.loads(proc.stdout)
        return results if isinstance(results, list) and len(results) == len(requests) else [None] * len(requests)
    except (OSError, subprocess.SubprocessError, ValueError):
        return [None] * len(requests)

def _build_retry_user_prompt(user_prompt: str, updated_prompt: dict) -> str:
    exploit_code = extract_js_triple_backticks(updated_prompt.get("response", ""))
    console_log = updated_prompt.get("console_log", [])
    console_log_text = json.dumps(console_log, indent=4, ensure_ascii=False)
    sections = [user_prompt]

    if exploit_code:
        sections.append(
            "## Previous exploit code\n"
            f"```js\n{exploit_code}\n```"
        )

    sections.append(
        "## Console log from running the generated script:\n"
        f"{console_log_text}"
    )

    return "\n\n".join(sections)


def _save_review_prompt(data: dict, system_prompt: str, user_prompt: str) -> Path:
    """Save the rendered first-attempt prompt so it can be reviewed before use."""
    output_dir = Path(os.environ.get("RUN_OUTPUT_DIR", "./logs"))
    prompt_dir = output_dir / "prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)

    raw_id = str(data.get("testbed_dir") or data.get("id") or "unknown")
    safe_id = "".join(char if char.isalnum() or char in "._-" else "_" for char in raw_id)
    prompt_path = prompt_dir / f"{safe_id}.exploit-prompt.txt"
    # Unconditionally strip baked-in static analysis before saving
    safe_user = _strip_static_analysis(user_prompt)
    prompt_path.write_text(
        "## System prompt\n"
        f"{system_prompt}\n\n"
        "## User prompt\n"
        f"{safe_user}\n",
        encoding="utf-8",
    )
    return prompt_path


def _extract_exploit_context(data: dict) -> dict:
    """Normalise both the old vfc-keyed shape and the new predicted shape into one dict."""
    generated = data.get('generated') or {}
    potential_vuln = generated.get('potential_vulnerability') or {}
    code_changes = data.get('source_code_changes', [])
    return {
        'package': data.get('vulnerable_package', ''),
        'vulnerability_type': potential_vuln.get('potential_vulnerability_type', ''),
        'commit_message': data.get('commit_message', ''),
        'code_changes': [{'filename': c.get('filename', ''), 'patch': c.get('patch', '')} for c in code_changes],
        'vulnerability_description': potential_vuln.get('vulnerability_description', ''),
        'vulnerable_api': potential_vuln.get('potential_vulnerable_API', ''),
    }


def generate_exploit(data: dict):
    prompts = []

    ctx = _extract_exploit_context(data)
    package = ctx['package'] or data.get('testbed_dir', 'unknown')
    vulnerability_type = ctx['vulnerability_type']
    if vulnerability_type == 'benign':
        tqdm.write(f"  [SKIP] {package} marked as benign")
        return []
    
    goal = CWE_MAP.get(vulnerability_type, {}).get('attack_goal', 'trigger vulnerability')

    static_analysis_enabled = _static_analysis_enabled()
    sa_context = _format_static_analysis_context(data, enabled=static_analysis_enabled)
    patch_context = f"Patch Context\nCommit message: {ctx['commit_message']}"
    if not static_analysis_enabled:
        patch_context += "\nCode Changes:\n" + json.dumps(ctx['code_changes'], indent=4)

    base_prompt = EXPLOIT_GENERATE_LLM_USER_PROMPT.format(
        package=package,
        vulnerability_type=vulnerability_type,
        goal=goal,
        vulnerability_description=ctx['vulnerability_description'],
        vulnerable_api=ctx['vulnerable_api'],
        patch_context=patch_context,
    )
    user_prompt = (
        base_prompt.rstrip() + '\n\nStatic Analysis Context\n' + sa_context
        if sa_context.strip()
        else base_prompt
    )

    system_prompt = EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT
    prompt_path = _save_review_prompt(data, system_prompt, user_prompt)
    tqdm.write(f"  [PROMPT] Saved for review: {prompt_path}")

    prompt_user_prompt = user_prompt
    updated_prompt = None
    exploit_result = False

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        attempt_start = time.time()
        tqdm.write(f"  → [{package}] Attempt {attempt}/{max_attempts} running...", end="")

        response = call_llm(
            prompt=prompt_user_prompt,
            system_prompt=system_prompt
        )
        response_text = response["choices"][0]["message"]["content"].strip()
        usage = response.get("usage")

        prompt = {
            'systemPrompt': system_prompt,
            'userPrompt': prompt_user_prompt,
            'response': response_text,
            'usage_summary': usage
        }

        updated_prompt, exploit_result = run_verifier(prompt, data)
        prompts.append(updated_prompt)

        elapsed = time.time() - attempt_start
        status = "PASSED" if exploit_result else "FAILED"
        status_color = "\033[92mPASSED\033[0m" if exploit_result else "\033[91mFAILED\033[0m"

        tqdm.write(f"\r  → [{package}] Attempt {attempt}/{max_attempts}: {status_color} ({elapsed:.1f}s)")

        if exploit_result:
            break

        prompt_user_prompt = _build_retry_user_prompt(user_prompt, updated_prompt)

    return prompts


if __name__ == "__main__":
    from pathlib import Path
    import time
    from src.utils import load_json, dump_jsonl, load_text
    from src.config import DATASET_LIST

    output_dir = os.environ.get("RUN_OUTPUT_DIR", "./logs")
    dataset_name = DATASET_LIST.split('/')[-1]
    output_path = Path(output_dir) / f'vfcs.generated.{dataset_name}.jsonl'

    predicted_path = Path(output_dir) / 'vfcs.predicted.json'
    if predicted_path.exists():
        data = load_json(predicted_path)
    else:
        print(f"Error: Could not find predictions at {predicted_path}")
        exit(1)

    print(f"Total loaded: {len(data)}")

    ids = set(id.replace(':', '_') for id in load_text(DATASET_LIST).splitlines())
    data = [d for d in data if d.get('testbed_dir') in ids]
    print(f"Processing {len(data)} items from dataset list")

    processed_dirs: set[str] = set()
    if output_path.exists():
        with open(output_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    datapoint = json.loads(line)
                    testbed = datapoint.get('testbed_dir')
                    if testbed:
                        processed_dirs.add(testbed)
                except json.JSONDecodeError:
                    pass
        print(f"Resuming: {len(processed_dirs)} already written to output, skipping")

    remaining = [d for d in data if d.get('testbed_dir') not in processed_dirs]
    print(f"After resume skip: {len(remaining)} items to process")

    start_time = time.time()

    for datapoint in tqdm(
        remaining,
        total=len(data),
        initial=len(processed_dirs),
        desc="Generating exploits",
        unit="item",
    ):
        datapoint_start = time.time()
        testbed = datapoint.get('testbed_dir', 'unknown')

        try:
            prompts = generate_exploit(datapoint)
        except Exception as e:
            tqdm.write(f"\nFAILED for {testbed}: ({e})")
            prompts = []

        datapoint.update(
            {
                'generated_exploits': prompts,
                'generation_time': time.time() - datapoint_start,
            }
        )

        with open(output_path, 'a') as f:
            f.write(json.dumps(datapoint, ensure_ascii=False) + '\n')

    total_elapsed = time.time() - start_time
    print(f"\nSuccessfully wrote generated exploits to {output_path} ({total_elapsed:.1f}s)")
