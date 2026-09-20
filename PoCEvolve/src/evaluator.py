import json
import re

from src.llm import call_llm
from src.utils import extract_js_triple_backticks
from src.verify import run_exploit
from src.prompts import (
    FEEDBACK_LLM_SYSTEM_PROMPT,
    SCORING_LLM_SYSTEM_PROMPT
)
from src.config import (
    CWE_MAP,
    MAX_EXEC_OUTPUT_CHARS,
    MAX_EXECUTION_OUTPUTS_IN_FEEDBACK,
)


def _truncate_text(text: str, max_chars: int) -> str:
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n...[truncated {omitted} chars]"


def parse_vfc_to_string(vfc: dict) -> str:
    if not isinstance(vfc, dict) or not vfc:
        return "No vulnerability fixing commit details available."

    commit_message = str(vfc.get("commit_message", "")).strip()
    code_changes = vfc.get("code_changes", [])

    lines: list[str] = []
    lines.append("Vulnerability Fixing Commit")
    lines.append("=" * 27)
    lines.append(f"Commit message: {commit_message or 'N/A'}")

    if not isinstance(code_changes, list) or not code_changes:
        lines.append("\nCode changes: N/A")
        return "\n".join(lines)

    lines.append(f"\nCode changes ({len(code_changes)} file(s)):")
    for index, change in enumerate(code_changes, start=1):
        if not isinstance(change, dict):
            lines.append(f"\n[{index}] Invalid code change entry")
            lines.append(str(change))
            continue

        filename = str(change.get("filename", "unknown"))
        patch = str(change.get("patch", ""))

        lines.append(f"\n[{index}] File: {filename}")
        lines.append("Patch:")
        lines.append(patch if patch else "N/A")

    return "\n".join(lines)


def _process_prompt(args):

    prompt, data = args
    local_exploit_result = False


    package = data.get("package") or data.get("vulnerable_package")
    version = data.get("version") or data.get("vulnerable_version")
    vulnerability_type = data["vulnerability_type"]
    if not isinstance(vulnerability_type, list):
        vulnerability_type = [vulnerability_type]
    vfc = data.get("vfc", {})
    if not vfc:
        commit_message = data.get('commit_message')
        code_changes = data.get('source_code_changes')
        vfc = {
            'commit_message': commit_message,
            'code_changes': code_changes,
        }
    response = prompt.get("response", "")
    

    exploit_code = extract_js_triple_backticks(response)
    if exploit_code and package and package not in exploit_code:
        prompt["console_log"] = []
        prompt["feedback"] = (
            f"1. Why the PoV code failed?\n"
            f"    1.1. Based on the generated code not importing or referencing `{package}`, hence the exploit does not exercise the vulnerable package at all.\n"
            f"    1.2. Based on the absence of any `require`/`import` for `{package}`, hence the vulnerability cannot be triggered without loading the target module.\n"
            f"2. How to improve the user_prompt to address this problem?\n"
            f"    2.1. Add an explicit instruction to the user_prompt that `{package}` must be required/imported and its vulnerable API must be called directly in the exploit would solve the 1.1 issue.\n"
            f"    2.2. Replace any generic exploit template in the user_prompt with one that starts by loading `{package}` before invoking the target function would solve the 1.2 issue."
        )
        return prompt, False

    if len(exploit_code) != 0:
        exploit_results = run_exploit(exploit_code, data)
        if not exploit_results:
            raise Exception("run_exploit: notthing from run_exploit")
    else:
        exploit_results = []
    

    prompt["console_log"] = [
        {
            "vulnerability_type": vulnerability_type,
            "command": command,
            "stdout": _truncate_text(stdout, MAX_EXEC_OUTPUT_CHARS),
            "stderr": _truncate_text(stderr, MAX_EXEC_OUTPUT_CHARS),
            "status": status,
        }
        for vulnerability_type, command, stdout, stderr, status in exploit_results
    ]


    success_results = [result for result in exploit_results if result[4] == 1]
    if success_results:
        local_exploit_result = True
        prompt["feedback"] = (
            "The exploit ran successfully "
            f"for {len(success_results)}/{len(exploit_results)} verification runs."
        )
        return prompt, local_exploit_result
    

    run_output_sections = []
    limited_results = exploit_results[:MAX_EXECUTION_OUTPUTS_IN_FEEDBACK]
    for run_index, (run_type, command, stdout, stderr, status) in enumerate(limited_results, start=1):
        run_output_sections.append(
            f"Run #{run_index} ({run_type}) status={status}\n"
            f"Command:\n{command}\n"
            f"STDOUT:\n{_truncate_text(stdout, MAX_EXEC_OUTPUT_CHARS) or ''}\n"
            f"STDERR:\n{_truncate_text(stderr, MAX_EXEC_OUTPUT_CHARS) or ''}"
        )
    if len(exploit_results) > len(limited_results):
        run_output_sections.append(
            f"...omitted {len(exploit_results) - len(limited_results)} run output(s) to control memory usage."
        )
    run_outputs = "\n\n".join(run_output_sections)


    goals = []
    for type in vulnerability_type:
        goals.append(CWE_MAP[type]['attack_goal'])
    if len(goals) == 1:
        goal_text = goals[0]
    else:
        goal_text = ""
        for i, goal in enumerate(goals):
            goal_text += goal
            if i + 1 != len(goals):
                goal_text += ' or '


    if len(vulnerability_type) == 1:
        vuln_type_text = vulnerability_type[0]
    else:
        vuln_type_text = ""
        for i, vuln_type in enumerate(vulnerability_type):
            vuln_type_text += vuln_type
            if i + 1 != len(vulnerability_type):
                vuln_type_text += ' or '


    context = {
        "user_prompt": prompt.get('userPrompt'),
        "response": response if len(response) > 0 else "The other LLM failed to generate the response for this `user_prompt`.",
    }
    task = "Score the `user_prompt`"

    llm_prompt = (
        f"Task: {task}\n\n"
        f"Context:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
    )
    llm_output = call_llm(
        system_prompt=SCORING_LLM_SYSTEM_PROMPT,
        prompt=llm_prompt,
        response_format={"type": "json_object"}
    )
    
    prompt["scores_usage_summary"] = llm_output.get("usage")
    raw_content = llm_output["choices"][0]["message"]["content"].strip()
    
    try:
        # Strip markdown fences if hallucinated
        cleaned = re.sub(r'^```(?:json)?\s*', '', raw_content, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s*```$', '', cleaned)
        
        # Extract strictly between the outermost brackets
        start_idx = cleaned.find('[')
        end_idx = cleaned.rfind(']') + 1
        
        if start_idx != -1 and end_idx > start_idx:
            cleaned = cleaned[start_idx:end_idx]
            
        prompt["scores_json"] = json.loads(cleaned)
    except json.JSONDecodeError:
        print(f"[WARN] GEPA scoring JSON parse failed. Output: {raw_content}")
        prompt["scores_json"] = [] # Fallback to prevent loop termination
        
    # Defensively parse scores regardless of whether the model returned dicts, numbers, or strings
    scores_parsed = []
    if isinstance(prompt["scores_json"], list):
        for item in prompt["scores_json"]:
            if isinstance(item, dict):
                val = item.get('score', 0)
                try:
                    scores_parsed.append(float(val))
                except (ValueError, TypeError):
                    scores_parsed.append(0.0)
            elif isinstance(item, (int, float)):
                scores_parsed.append(float(item))
            elif isinstance(item, str):
                try:
                    scores_parsed.append(float(item))
                except ValueError:
                    scores_parsed.append(0.0)
                    
    prompt["scores"] = scores_parsed
    prompt["avg_score"] = sum(prompt["scores"]) / len(prompt["scores"]) if prompt["scores"] else 0
        

    context = {
        "user_prompt": prompt.get('userPrompt'),
        "response": response if len(response) > 0 else "The other LLM failed to generate the response for this `user_prompt`.",
        "proof_of_vulnerability_code": exploit_code if len(exploit_code) > 0 else "Was not able to extract the PoV code from `response`.",
        "execution_outputs": run_outputs if len(run_outputs) > 0 else "Was not able to run the PoV code from the `response`.",
        "vulnerabilty_fixing_commit": parse_vfc_to_string(vfc),
        "package": package,
        "version": version,
        "vulnerability_type": vuln_type_text,
        "goals": goal_text,
        "scores": prompt["scores_json"]
    }
    task = (
        f"Why the proof of vulnerability code failed to {goal_text}? "
        "How do we fix it by modifying the user prompt used the generate this proof of vulnerability?"
    )
    llm_prompt = (
        f"Task: {task}\n\n"
        f"Context:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
        "Provide concise feedback focused on how to revise the user prompt."
    )
    llm_output = call_llm(
        system_prompt=FEEDBACK_LLM_SYSTEM_PROMPT,
        prompt=llm_prompt,
    )
    prompt["feedback_usage_summary"] = llm_output.get("usage")
    prompt["feedback"] = llm_output["choices"][0]["message"]["content"].strip()
    return prompt, local_exploit_result


def evaluation_and_feedback_function(prompts: list, data: dict):
    exploit_result = False
    updated_prompts = []

    for prompt in prompts:
        task = (prompt, data)
        prompt, local_exploit_result = _process_prompt(task)
        updated_prompts.append(prompt)
        if local_exploit_result:
            exploit_result = True

    return updated_prompts, exploit_result