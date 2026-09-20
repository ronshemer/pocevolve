import os
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from src.utils import load_json, dump_json
from src.llm import call_llm
from src.config import MAX_WORKERS
from src.prompts import VULNERABILITY_REPORT_SYSTEM_PROMPT

def _parse_json_object(text: str) -> dict | None:
    """Extract the first valid JSON object from an LLM response."""
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def generate_vulnerability_description(data: dict) -> None:
    user_prompt = json.dumps({
        'vulnerable_package': data.get('vulnerable_package', ''),
        'vulnerable_version': data.get('vulnerable_version', ''),
        'commit_message': data.get('commit_message', ''),
        'source_code_changes': data.get('source_code_changes', '')
    }, indent=4)

    response_json = None
    response = None
    parse_prompt = user_prompt
    for attempt in range(1, 3):
        response = call_llm(
            prompt=parse_prompt,
            system_prompt=VULNERABILITY_REPORT_SYSTEM_PROMPT
        )
        response_text = response["choices"][0]["message"]["content"].strip()
        response_json = _parse_json_object(response_text)
        if response_json is not None:
            break
        tqdm.write(f"Failed to parse vulnerability JSON (attempt {attempt}/2); retrying")
        parse_prompt = (
            user_prompt
            + "\n\nYour previous response was not valid JSON. Return only one valid JSON object "
              "with exactly the requested fields; do not use markdown or surrounding text."
        )

    if response_json is None:
        # Keep the record explicit so downstream evaluation cannot mistake an
        # empty description for a successfully analyzed vulnerability.
        response_json = {"analysis_error": "invalid_json_response"}
        
    usage = response.get("usage") if response else None

    data.update({
        'generated': {
            'potential_vulnerability': response_json,
            'usage': usage
        }
    })

if __name__ == "__main__":
    output_dir = os.environ.get("RUN_OUTPUT_DIR", "./logs")
    predicted_path = Path(output_dir) / 'vfcs.predicted.json'
    
    if predicted_path.exists():
        data = load_json(predicted_path)
    else:
        data = load_json('./secbenchjs/vfcs.filtered.json')
        data = [d for d in data if len(d.get('source_code_changes', [])) > 0]

        # Apply filtering based on the active DATASET env variable
        dataset_path = os.environ.get("DATASET")
        if dataset_path and Path(dataset_path).exists():
            with open(dataset_path, 'r') as f:
                # Extract clean IDs (handles converting colons to underscores if needed)
                valid_ids = set(line.strip().replace(':', '_') for line in f if line.strip())
            
            # Filter the loaded data down to only the target items
            data = [
                d for d in data 
                if d.get('testbed_dir', d.get('id', '')).replace(':', '_') in valid_ids
            ]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            list(tqdm(
                executor.map(generate_vulnerability_description, data), 
                total=len(data), 
                desc='Generating vulnerability descriptions'
            ))

        predicted_path.parent.mkdir(parents=True, exist_ok=True)
        dump_json(data, predicted_path)

    print(f"Total loaded: {len(data)}")
