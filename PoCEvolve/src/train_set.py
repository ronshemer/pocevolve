from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import json
import threading

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_distances

POCGEN_DIR = "./final-exp-outputs/jit/pocgen/qwen3.7-plus"
DATASET_LIST = "./datasets/SecBench.js.PoCGen.vfc.190"
VFCS_JSON = './secbenchjs/vfcs.json'
OUTPUT_DIR =  "./training-set"
MAX_WORKERS = 10
FILTERED_K = 5

_MODEL: SentenceTransformer | None = None
_MODEL_LOCK = threading.Lock()
_ENCODE_LOCK = threading.Lock()


def get_model() -> SentenceTransformer:
    global _MODEL
    if _MODEL is None:
        with _MODEL_LOCK:
            if _MODEL is None:
                _MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _MODEL


def build_vfc_index(vfcs_json_path: str) -> dict:
    entries = json.loads(Path(vfcs_json_path).read_text()) if Path(vfcs_json_path).exists() else []
    index = {}
    for entry in entries:
        for vid in entry.get("ids", []):
            index[vid] = entry
        testbed = entry.get("testbed_dir")
        if testbed:
            index[testbed] = entry
    return index


def normalize_unique_prompt_entries(prompt_entries):
    cleaned_entries = []
    seen_prompts = set()

    for prompt_obj in prompt_entries or []:
        if not isinstance(prompt_obj, dict):
            continue
        prompt_text = (prompt_obj.get("userPrompt") or "").strip()
        if not prompt_text or prompt_text in seen_prompts:
            continue

        seen_prompts.add(prompt_text)
        normalized_prompt_obj = dict(prompt_obj)
        normalized_prompt_obj["userPrompt"] = prompt_text
        cleaned_entries.append(normalized_prompt_obj)

    return cleaned_entries


def pick_most_diverse_semantic(strings, k=5):
    unique_strings = []
    seen_strings = set()
    for value in strings:
        if not isinstance(value, str):
            continue
        normalized_value = value.strip()
        if not normalized_value or normalized_value in seen_strings:
            continue
        seen_strings.add(normalized_value)
        unique_strings.append(normalized_value)

    if not unique_strings or k <= 0:
        return []
    if len(unique_strings) <= k:
        return unique_strings

    model = get_model()
    with _ENCODE_LOCK:
        vecs = model.encode(unique_strings, convert_to_numpy=True, normalize_embeddings=True)
    dist = cosine_distances(vecs)

    chosen = [int(np.argmax(dist.sum(axis=1)))]
    while len(chosen) < k and len(chosen) < len(unique_strings):
        scores = np.min(dist[:, chosen], axis=1)
        scores[chosen] = -1
        chosen.append(int(np.argmax(scores)))

    return [unique_strings[i] for i in chosen]


def filter_prompt_entries_by_diversity(prompt_entries, k=5):
    unique_entries = normalize_unique_prompt_entries(prompt_entries)
    if len(unique_entries) <= k:
        return unique_entries

    unique_texts = [entry["userPrompt"] for entry in unique_entries]
    selected_texts = set(pick_most_diverse_semantic(unique_texts, k=k))

    selected_entries = []
    for entry in unique_entries:
        prompt_text = entry["userPrompt"]
        if prompt_text in selected_texts:
            selected_entries.append(entry)
            selected_texts.remove(prompt_text)
        if not selected_texts:
            break

    return selected_entries


def process_datapoint(datapoint: str, testbed_dir: Path, training_set_dir: Path, vfc_index: dict) -> None:
    if len(datapoint) == 0:
        return

    try:
        raw_datapoint = datapoint
        new_datapoint = {
            "id": raw_datapoint,
            "exploit_result": False,
            "package": "",
            "version": "",
            "vulnerability_type": [],
            "prompts": [],
            "refinement-attempts": [],
            "seen_prompts": [],
            "seen_exploits": [],
            "vfc": {},
        }

        datapoint = datapoint.replace(":", "_")

        training_set_id_dir = training_set_dir / f"{datapoint}.json"
        if not training_set_id_dir.exists():
            training_set_id_dir.parent.mkdir(parents=True, exist_ok=True)
        prompts_dir = testbed_dir / datapoint / "prompt.json"
        result_report_dir = testbed_dir / datapoint / "RunnerResult_DefaultRefiner.json"

        prompts = json.loads(prompts_dir.read_text()) if prompts_dir.exists() else []
        new_datapoint["prompts"] += prompts

        result_report: dict = json.loads(result_report_dir.read_text()) if result_report_dir.exists() else {}
        if not result_report:
            return

        if "exploitSuccessResult" in result_report:
            if result_report["exploitSuccessResult"]:
                return

        seen_exploits: list = result_report["seenExploits"]
        new_datapoint['seen_exploits'] = seen_exploits

        llm_identified_vulnerability_types: list = result_report["llmIdentifiedVulnerabilityTypes"]
        for vulnerability_type in llm_identified_vulnerability_types:
            if vulnerability_type is None:
                continue
            new_datapoint["vulnerability_type"].append(vulnerability_type["label"])

        advisory = result_report["advisory"]
        package = advisory["package"]["name"]
        version = advisory["package"]["version"]
        new_datapoint["package"] = package
        new_datapoint["version"] = version

        exploit_attempts: list = result_report["exploitAttempts"]
        exploit_attempt: dict
        for exploit_attempt in exploit_attempts:
            prompt_refiners = exploit_attempt['promptRefiners']
            for prompt_refiner in prompt_refiners:
                refinement_attempts: int = prompt_refiner['refinementAttempts']
                seen_prompts: list = prompt_refiner['seenPrompts']

                for seen_prompt in seen_prompts:
                    for prompt in prompts:
                        if seen_prompt == prompt["prompt"]:
                            response = prompt["response"]["completions"][0]
                            seen_prompt["response"] = response

                if refinement_attempts > -1 and len(seen_prompts) != 0:
                    new_datapoint['refinement-attempts'].append(refinement_attempts)
                    new_datapoint['seen_prompts'].append(seen_prompts)

        filtered_seen_prompt_groups = []
        for seen_prompt_group in new_datapoint["seen_prompts"]:
            filtered_seen_prompt_groups.append(
                filter_prompt_entries_by_diversity(seen_prompt_group, k=FILTERED_K)
            )
        new_datapoint[f"seen_prompts_filtered_k{FILTERED_K}"] = filtered_seen_prompt_groups

        _VFC_FIELDS = {
            "commit_message", "source_code_changes", "number_code_changes",
            "all_code_changes", "number_all_code_changes", "pr_title",
            "pr_description", "discussion_comments", "vulnerability_fix_commit",
            "commit_type",
        }
        vfc_entry = vfc_index.get(raw_datapoint) or vfc_index.get(datapoint)
        if vfc_entry:
            new_datapoint["vfc"] = {k: v for k, v in vfc_entry.items() if k in _VFC_FIELDS}

        training_set_id_dir.write_text(json.dumps(new_datapoint, indent=4))
    except Exception as error:
        print(f"Error processing datapoint '{datapoint}': {error}")
        # traceback.print_exc()

def main():
    with open(DATASET_LIST, "r", encoding="utf-8") as f:
        data = f.read().splitlines()
    testbed_dir = Path(POCGEN_DIR)
    training_set_dir = Path(OUTPUT_DIR)
    vfc_index = build_vfc_index(VFCS_JSON)

    non_empty_data = [datapoint for datapoint in data if len(datapoint) != 0]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(process_datapoint, datapoint, testbed_dir, training_set_dir, vfc_index)
            for datapoint in non_empty_data
        ]
        for future in tqdm(as_completed(futures), total=len(futures)):
            future.result()

if __name__ == "__main__":
    main()