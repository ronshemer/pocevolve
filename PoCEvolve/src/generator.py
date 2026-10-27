import json
import logging
import os
import re
import time
from pathlib import Path
from tqdm import tqdm

from src.utils import load_json, extract_js_triple_backticks
from src.llm import call_llm
from src.prompts import (
    EXPLOIT_GENERATE_LLM_USER_PROMPT,
    EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT
)
from src.config import CWE_MAP, DATASET_LIST, MAX_GENERATION_ATTEMPTS, GEPA_LOG_DIR
from src.verify import run_verifier

logger = logging.getLogger(__name__)
MAX_STATIC_SOURCE_CONTEXT_CHARS = 20_000
STATIC_SOURCE_WINDOW_CHARS = 500


def _static_analysis_enabled() -> bool:
    return os.environ.get("USE_STATIC_ANALYSIS", "1").strip().lower() in {"1", "true", "yes", "on"}


def _format_static_analysis_context(data: dict) -> str:
    """Run the snapshot branch's AST analyzer and format its API/method findings."""
    testbed_dir = str(data.get("testbed_dir") or data.get("id") or "").strip()
    if not testbed_dir:
        return "Static analysis unavailable: this record has no CVE or testbed identifier."

    try:
        from src.graph_analysis import analyze_cve
        from src.graph_analysis.testbed_manager import ensure_git_testbed
        from src.graph_analysis.vfc_loader import get_diff

        package_root = ensure_git_testbed(testbed_dir)
        diff_text = get_diff(
            testbed_dir=testbed_dir,
            cve_id=testbed_dir,
            fix_commit_url=data.get("vulnerability_fix_commit") or None,
        ) or ""
        result = analyze_cve(
            cve_id=testbed_dir,
            package_root=package_root,
            diff_text=diff_text,
            testbed_dir=testbed_dir,
        )
        source_context = _extract_referenced_method_sources(package_root, result)
    except Exception as exc:
        tqdm.write(f"  [WARN] Static analysis unavailable for {testbed_dir}: {exc}")
        return f"Static analysis unavailable for {testbed_dir}: {exc}"

    sections = []
    if result.entry_points:
        sections.append("Package entry points:")
        for entry_point in result.entry_points:
            if isinstance(entry_point, dict):
                file_path = entry_point.get("file_path", "unknown file")
                methods = entry_point.get("exported_methods")
                description = file_path
                if methods is not None:
                    description += f" (exported methods: {', '.join(methods) if methods else 'none identified'})"
                sections.append(f"- {description}")
            else:
                sections.append(f"- {entry_point}")
    else:
        sections.append("Package entry points: none identified.")

    if result.target_methods:
        sections.append("Methods affected by the fix:")
        for method in result.target_methods:
            file_path = method.get("file_path", "unknown file")
            method_name = method.get("method_name", "unknown method")
            lines = method.get("deleted_lines") or method.get("added_line_anchors") or []
            change_type = method.get("change_type", "unknown")
            details = f"{file_path}#{method_name} ({change_type} change"
            if lines:
                details += f", vulnerable-source lines: {', '.join(map(str, lines))}"
            details += ")"
            sections.append(f"- {details}")
    else:
        sections.append("Methods affected by the fix: none identified.")

    sections.append("Referenced method source code from the vulnerable checkout:")
    sections.extend(source_context)
    sections.append(
        "Use these static results as navigation hints when choosing how to trigger "
        "the vulnerability."
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
    fallback_paths = {
        request[0]
        for request, found in zip(unique_requests, extracted)
        if not found
    }
    full_file_fallbacks = set()
    seen_snippets = set()
    for request, found in zip(unique_requests, extracted):
        relative_path, method_name, _line_number = request
        if relative_path in fallback_paths:
            if relative_path in full_file_fallbacks:
                continue
            try:
                source = (root / relative_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                full_file_fallbacks.add(relative_path)
                continue
            full_file_fallbacks.add(relative_path)
            reason = "entry file" if method_name == "<entry file>" else f"target file; could not isolate {method_name}"
            snippets.append(
                f"\n### {relative_path} — full {reason}\n"
                f"```text\n{source}\n```"
            )
            continue

        if found:
            snippet_key = (found["file_path"], found["code"])
            if snippet_key in seen_snippets:
                continue
            seen_snippets.add(snippet_key)
            snippets.append(
                f"\n### {found['file_path']} — {found['signature']}\n"
                f"```javascript\n{found['code']}\n```"
            )

    if sum(map(len, snippets)) > MAX_STATIC_SOURCE_CONTEXT_CHARS:
        snippets = _bounded_target_source_context(
            root,
            result.target_methods,
            max_chars=MAX_STATIC_SOURCE_CONTEXT_CHARS,
            window_chars=STATIC_SOURCE_WINDOW_CHARS,
        )

    return snippets or ["- No referenced method bodies could be extracted from the vulnerable source checkout."]


def _bounded_target_source_context(
    package_root: Path,
    target_methods: list[dict],
    *,
    max_chars: int,
    window_chars: int,
) -> list[str]:
    """Prefer whole affected files, then bound remaining files around vulnerable-side diff lines."""
    root = package_root.resolve()
    grouped: dict[str, dict] = {}
    for method in target_methods:
        relative_path = method.get("file_path")
        lines = method.get("deleted_lines") or method.get("added_line_anchors") or []
        if not relative_path or not lines:
            continue
        path = (root / str(relative_path)).resolve()
        try:
            relative_path = path.relative_to(root).as_posix()
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue

        item = grouped.setdefault(relative_path, {"source": source, "lines": []})
        item["lines"].extend(int(line) for line in lines if str(line).isdigit())

    windows_by_path = []
    for relative_path, item in grouped.items():
        source = item["source"]
        line_starts = [0]
        for match in re.finditer("\n", source):
            line_starts.append(match.end())
        ranges = []
        for line_number in sorted(set(item["lines"])):
            if line_number < 1 or line_number > len(line_starts):
                continue
            start = line_starts[line_number - 1]
            end = line_starts[line_number] if line_number < len(line_starts) else len(source)
            start = max(0, start - window_chars)
            end = min(len(source), end + window_chars)
            while start > 0 and source[start - 1] != "\n":
                start -= 1
            while end < len(source) and (end == 0 or source[end - 1] != "\n"):
                end += 1
            ranges.append((start, end, [line_number]))

        merged = []
        for start, end, lines in ranges:
            if merged and start <= merged[-1][1]:
                old_start, old_end, old_lines = merged[-1]
                merged[-1] = (old_start, max(old_end, end), old_lines + lines)
            else:
                merged.append((start, end, lines))
        if merged:
            windows_by_path.append((relative_path, source, merged))

    if not windows_by_path:
        return ["- Full source omitted: no vulnerable-source line anchors were available for bounded context."]

    snippets = []
    used_chars = 0
    omitted = False
    note = "\n- Additional source windows omitted to stay within the 20,000-character static context limit."
    for relative_path, source, windows in windows_by_path:
        full_block = (
            f"\n### {relative_path} — full affected target file\n"
            f"```text\n{source}\n```"
        )
        remaining = max_chars - len(note) - used_chars
        if len(full_block) <= remaining:
            snippets.append(full_block)
            used_chars += len(full_block)
            continue

        for start, end, lines in windows:
            header = (
                f"\n### {relative_path} — source window around vulnerable-source line(s) "
                f"{', '.join(map(str, lines))}\n```text\n"
            )
            block = header + source[start:end] + "\n```"
            remaining = max_chars - len(note) - used_chars
            if len(block) > remaining:
                omitted = True
                continue
            snippets.append(block)
            used_chars += len(block)

    if omitted:
        snippets.append(note)
    return snippets


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
    """Use Python Tree-sitter to resolve requested JavaScript method bodies."""
    try:
        import tree_sitter_javascript as javascript
        from tree_sitter import Language, Parser
    except ImportError as exc:
        logger.warning("Tree-sitter JavaScript dependencies are unavailable: %s", exc)
        return [None] * len(requests)

    parser = Parser(Language(javascript.language()))
    indexed: dict[str, list[dict]] = {}

    def property_name(node) -> str:
        if node is None:
            return ""
        if node.type in {"identifier", "property_identifier", "private_property_identifier"}:
            return node.text.decode("utf-8", errors="replace")
        if node.type == "member_expression":
            return property_name(node.child_by_field_name("property"))
        if node.type == "subscript_expression":
            subscript = node.child_by_field_name("index")
            return property_name(subscript)
        return ""

    def callable_name(node) -> str:
        name = node.child_by_field_name("name")
        if name is not None:
            return property_name(name)
        parent = node.parent
        if parent is None:
            return ""
        if parent.type == "variable_declarator":
            return property_name(parent.child_by_field_name("name"))
        if parent.type == "assignment_expression":
            return property_name(parent.child_by_field_name("left"))
        if parent.type == "pair":
            return property_name(parent.child_by_field_name("key"))
        return ""

    callable_types = {
        "function_declaration", "function_expression", "generator_function",
        "generator_function_declaration", "arrow_function", "method_definition",
    }
    for relative_path in files:
        try:
            source = (package_root / relative_path).read_bytes()
        except OSError:
            continue
        tree = parser.parse(source)
        if tree is None:
            continue
        methods = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in callable_types:
                methods.append({
                    "name": callable_name(node),
                    "start_line": node.start_point.row + 1,
                    "end_line": node.end_point.row + 1,
                    "span": node.end_byte - node.start_byte,
                    "code": source[node.start_byte:node.end_byte].decode("utf-8", errors="replace"),
                })
            stack.extend(reversed(node.named_children))
        indexed[relative_path] = methods

    extracted = []
    for relative_path, requested_name, line_number in requests:
        if requested_name == "<entry file>":
            extracted.append(None)
            continue
        candidates = list(indexed.get(relative_path, []))
        if line_number is not None:
            candidates = [item for item in candidates if item["start_line"] <= line_number <= item["end_line"]]
        if requested_name != "<entry file>":
            short_name = requested_name.rsplit(".", 1)[-1]
            named = [item for item in candidates if item["name"] == short_name]
            if named:
                candidates = named
            elif line_number is None:
                candidates = [item for item in candidates if item["name"] == requested_name]
        if not candidates and line_number is None and requested_name != "<entry file>":
            short_name = requested_name.rsplit(".", 1)[-1]
            candidates = [
                item for methods in indexed.values() for item in methods
                if item["name"] in {requested_name, short_name}
            ]
        if not candidates:
            extracted.append(None)
            continue
        # Prefer the named enclosing method; otherwise take the broadest
        # callable around a changed line so the complete method is included.
        candidates.sort(key=lambda item: (-item["span"], item["start_line"]))
        found = candidates[0]
        extracted.append({
            "file_path": relative_path,
            "signature": found["name"] or requested_name,
            "code": found["code"],
        })
    return extracted

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
    package = ctx['package']
    vulnerability_type = ctx['vulnerability_type']
    if vulnerability_type == 'benign':
        return []
    
    goal = CWE_MAP[vulnerability_type]['attack_goal']

    static_analysis_enabled = _static_analysis_enabled()
    patch_context = f"Commit message: {ctx['commit_message']}"
    if static_analysis_enabled:
        patch_context += "\n\nStatic analysis results\n" + _format_static_analysis_context(data)
    else:
        patch_context += "\nCode changes:\n" + json.dumps(ctx['code_changes'], indent=4)

    user_prompt = EXPLOIT_GENERATE_LLM_USER_PROMPT.format(
        package=package,
        vulnerability_type=vulnerability_type,
        goal=goal,
        vulnerability_description=ctx['vulnerability_description'],
        vulnerable_api=ctx['vulnerable_api'],
        patch_context=patch_context,
    )

    system_prompt = EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT

    prompt_user_prompt = user_prompt
    updated_prompt = None
    exploit_result = False

    with tqdm(total=MAX_GENERATION_ATTEMPTS, desc=f"PoC attempts: {package}", unit="attempt", leave=True) as progress:
      for attempt in range(1, MAX_GENERATION_ATTEMPTS + 1):
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
          progress.update(1)
          progress.set_postfix_str("verified" if exploit_result else f"attempt {attempt} failed")
          if exploit_result:
              break

          prompt_user_prompt = _build_retry_user_prompt(user_prompt, updated_prompt)

    return prompts


if __name__ == "__main__":
    from pathlib import Path
    from src.utils import load_json, load_text

    output_path = GEPA_LOG_DIR / f'vfcs.generated.{Path(DATASET_LIST).name}.jsonl'
    predicted_path = GEPA_LOG_DIR / 'vfcs.predicted.json'
    if not predicted_path.exists():
        raise SystemExit(f"Missing vulnerability report checkpoint: {predicted_path}")
    data = load_json(predicted_path)
    print(f"Total loaded: {len(data)}")

    ids = {value.replace(':', '_') for value in load_text(DATASET_LIST).splitlines() if value.strip()}
    data = [d for d in data if d.get('testbed_dir', '').replace(':', '_') in ids]
    print(f"Processing {len(data)} items from dataset list")

    completed = {}
    if output_path.exists():
        valid_lines = []
        raw_lines = output_path.read_text(encoding='utf-8').splitlines()
        for line_number, line in enumerate(raw_lines, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                if line_number == len(raw_lines):
                    print(f"Discarding incomplete final checkpoint line in {output_path}")
                    break
                raise
            ident = str(row.get('testbed_dir', '')).replace(':', '_')
            if not ident:
                raise ValueError(f"Checkpoint line {line_number} has no testbed_dir")
            completed[ident] = row
            valid_lines.append(json.dumps(row, ensure_ascii=False))
        output_path.write_text('\n'.join(valid_lines) + ('\n' if valid_lines else ''), encoding='utf-8')

    unexpected = set(completed) - ids
    if unexpected:
        raise ValueError(f"Checkpoint contains IDs outside the requested dataset: {sorted(unexpected)}")
    pending = [d for d in data if str(d.get('testbed_dir', '')).replace(':', '_') not in completed]
    print(f"Already checkpointed: {len(completed)}; remaining: {len(pending)}")

    for datapoint in pending:
        datapoint_start = time.time()
        prompts = generate_exploit(datapoint)
        datapoint.update(
            {
                'generated_exploits': prompts,
                'generation_time': time.time() - datapoint_start,
            }
        )
        with output_path.open('a', encoding='utf-8') as checkpoint:
            checkpoint.write(json.dumps(datapoint, ensure_ascii=False) + '\n')
            checkpoint.flush()
