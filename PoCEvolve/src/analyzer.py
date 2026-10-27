import json
import re

from pathlib import Path
from src.utils import load_json, dump_json
from tqdm import tqdm

from src.llm import call_llm
from src.config import MAX_WORKERS, DATASET_LIST, GEPA_LOG_DIR
from src.prompts import VULNERABILITY_REPORT_SYSTEM_PROMPT


def save_checkpoint(path: Path, data: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _parse_vulnerability_response(response_text: str) -> dict:
    """Parse a JSON object even when the model wraps it in Markdown or brief prose."""
    text = response_text.strip()
    candidates = [text]

    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1).strip())

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start:end + 1])

    last_error = None
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("Vulnerability response JSON must be an object")

    raise ValueError(f"Could not parse vulnerability response as JSON: {last_error}")


def generate_vulnerability_description(data: dict) -> str:
    user_prompt = json.dumps({
        'vulnerable_package': data.get('vulnerable_package', ''),
        'vulnerable_version': data.get('vulnerable_version', ''),
        'commit_message': data.get('commit_message', ''),
        'source_code_changes': data.get('source_code_changes', '')
    }, indent=4)

    response = call_llm(
        prompt=user_prompt,
        system_prompt=VULNERABILITY_REPORT_SYSTEM_PROMPT
    )
    response_text = response["choices"][0]["message"]["content"].strip()
    print(response_text)
    response_json = _parse_vulnerability_response(response_text)
    usage = response.get("usage")

    data.update({
        'generated': {
            'potential_vulnerability': response_json,
            'usage': usage
        }
    })

if __name__ == "__main__":
    predicted_path = GEPA_LOG_DIR / 'vfcs.predicted.json'
    if predicted_path.exists():
        data = load_json(predicted_path)
    else:
        data = load_json('./secbenchjs/vfcs.filtered.json')
        data = [d for d in data if len(d.get('source_code_changes', [])) > 0]

    if DATASET_LIST:
        wanted = {line.strip().replace(':', '_') for line in Path(DATASET_LIST).read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')}
        data = [d for d in data if d.get('testbed_dir', d.get('id', '')).replace(':', '_') in wanted]

    pending = [d for d in data if not d.get('generated', {}).get('potential_vulnerability')]
    for record in tqdm(pending, total=len(pending), desc='Generating vulnerability descriptions'):
        generate_vulnerability_description(record)
        save_checkpoint(predicted_path, data)

    if not predicted_path.exists():
        save_checkpoint(predicted_path, data)
    print(f"Total loaded for this run: {len(data)}")
