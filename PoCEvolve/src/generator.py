import json
import time
from pathlib import Path

from src.utils import load_json, extract_js_triple_backticks
from src.llm import call_llm
from src.prompts import (
    EXPLOIT_GENERATE_LLM_USER_PROMPT,
    EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT
)
from src.config import CWE_MAP, DATASET_LIST
from src.verify import run_verifier

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

    user_prompt = EXPLOIT_GENERATE_LLM_USER_PROMPT.format(
        package=package,
        vulnerability_type=vulnerability_type,
        goal=goal,
        vulnerability_description=ctx['vulnerability_description'],
        vulnerable_api=ctx['vulnerable_api'],
        commit_message=ctx['commit_message'],
        code_changes=json.dumps(ctx['code_changes'], indent=4),
    )

    system_prompt = EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT

    prompt_user_prompt = user_prompt
    updated_prompt = None
    exploit_result = False

    for _ in range(5):
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
        if exploit_result:
            break

        prompt_user_prompt = _build_retry_user_prompt(user_prompt, updated_prompt)

    return prompts


if __name__ == "__main__":
    from pathlib import Path
    from src.utils import load_json, dump_jsonl, load_text

    output_path = Path(f'./logs/vfcs.generated.{DATASET_LIST.replace('/', '.')}.jsonl')
    if output_path.exists():
        print(f"Output already exists at {output_path}, skipping.")
        exit(0)

    predicted_path = Path('./path/to/analyzer/vfcs.predicted.json')
    if predicted_path.exists():
        data = load_json(predicted_path)
    else:
        exit(1)

    print(f"Total loaded: {len(data)}")

    ids = set(id.replace(':', '_') for id in load_text(DATASET_LIST).splitlines())
    data = [d for d in data if d.get('testbed_dir') in ids]
    print(f"Processing {len(data)} items from dataset list")

    start_time = time.time()

    for datapoint in data:
        datapoint_start = time.time()
        prompts = generate_exploit(datapoint)
        datapoint.update(
            {
                'generated_exploits': prompts,
                'generation_time': time.time() - datapoint_start,
            }
        )

    dump_jsonl(data, str(output_path))