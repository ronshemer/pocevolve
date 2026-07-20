import json

from pathlib import Path
from src.utils import load_json, dump_json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from src.llm import call_llm
from src.config import MAX_WORKERS
from src.prompts import VULNERABILITY_REPORT_SYSTEM_PROMPT


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
    response_json = json.loads(response_text)
    usage = response.get("usage")

    data.update({
        'generated': {
            'potential_vulnerability': response_json,
            'usage': usage
        }
    })

if __name__ == "__main__":
    predicted_path = Path('./logs/vfcs.predicted.json')
    if predicted_path.exists():
        data = load_json(predicted_path)
    else:
        data = load_json('./secbenchjs/vfcs.filtered.json')
        data = [d for d in data if len(d.get('source_code_changes', [])) > 0]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            list(tqdm(executor.map(generate_vulnerability_description, data), total=len(data), desc='Generating vulnerability descriptions'))

        dump_json(data, predicted_path)

    print(f"Total loaded: {len(data)}")