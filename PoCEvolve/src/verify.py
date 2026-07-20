from pathlib import Path

from src.config import TESTBED_DIR, VALIDATE_FUNC, EXPLOIT_CODE_TEMPLATE, VERIFY_TIME, MAX_EXEC_OUTPUT_CHARS
from src.utils import exec_command, dump_text, load_text, extract_js_triple_backticks


def _truncate_text(text: str, max_chars: int) -> str:
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n...[truncated {omitted} chars]"

def genpoc_reset():
    cmd = "/usr/bin/genpoc reset"
    stdout, stderr = exec_command(cmd)
    return stdout, stderr

def _run_single(args):
    exploit_func, attack_type, package, vulnerable_version, id, run_index = args

    genpoc_reset()

    validate_func_path = VALIDATE_FUNC[attack_type]
    validate_function = load_text(validate_func_path)

    exploit_code = EXPLOIT_CODE_TEMPLATE.format(
        exploit_function=exploit_func,
        validate_function=validate_function,
        attack_type=attack_type,
        package=package,
        vulnerable_version=vulnerable_version,
        id=id
    )

    testbed_dir = Path(TESTBED_DIR) / id.replace(":", "_") / f"{attack_type}_{run_index}"
    testbed_dir.mkdir(parents=True, exist_ok=True)
    testbed_path = testbed_dir / "gepa_test.js"
    dump_text(exploit_code, testbed_path)

    if attack_type == "redos":
        command = "node --test --enable-experimental-regexp-engine-on-excessive-backtracks --regexp-backtracks-before-fallback=30000 --no-warnings gepa_test.js"
    elif attack_type == "path-traversal":
        command = "node --test --test-force-exit --no-warnings gepa_test.js"
    else:
        command = "node --test --no-warnings gepa_test.js"
    stdout, stderr = exec_command(command, testbed_dir)

    exploit_result = 1 if "pass 1" in stdout else 0
    return (attack_type, command, stdout, stderr, exploit_result)


def run_exploit(exploit_func: str, data: str) -> list:
    attack_types = (
        data.get('generated', {})
            .get('potential_vulnerability', {})
            .get('potential_vulnerability_type')
        or data.get('vulnerability_type')
    )
    if not isinstance(attack_types, list):
        attack_types = [attack_types]
    package = data.get("package") or data.get("vulnerable_package")
    vulnerable_version = data.get("version") or data.get("vulnerable_version")
    id = data.get("id") or data.get("testbed_dir")

    if not package:
        raise ValueError("run_exploit requires a non-empty package or vulnerable_package")
    if not vulnerable_version:
        raise ValueError("run_exploit requires a non-empty version or vulnerable_version")
    if not id:
        raise ValueError("run_exploit requires a non-empty id or testbed_dir")

    tasks = [
        (exploit_func, attack_type, package, vulnerable_version, id, run_index)
        for attack_type in attack_types
        for run_index in range(VERIFY_TIME)
    ]

    results = []
    for task in tasks:
        results.append(_run_single(task))

    # Remove duplicate results while preserving the first-seen order.
    unique_results = list(dict.fromkeys(results))

    return unique_results


def run_verifier(prompt: dict, data: dict, max_output_chars: int = MAX_EXEC_OUTPUT_CHARS) -> tuple[dict, bool]:
    """Execute extracted PoV code and return updated prompt with verification logs."""
    response = prompt.get("response", "")

    exploit_code = extract_js_triple_backticks(response)
    if len(exploit_code) == 0:
        prompt["console_log"] = []
        return prompt, False

    exploit_results = run_exploit(exploit_code, data)
    if not exploit_results:
        prompt["console_log"] = []
        return prompt, False

    prompt["console_log"] = [
        {
            "vulnerability_type": vulnerability_type,
            "command": command,
            "stdout": _truncate_text(stdout, max_output_chars),
            "stderr": _truncate_text(stderr, max_output_chars),
            "status": status,
        }
        for vulnerability_type, command, stdout, stderr, status in exploit_results
    ]

    success_results = [result for result in exploit_results if result[4] == 1]
    if success_results:
        return prompt, True

    return prompt, False