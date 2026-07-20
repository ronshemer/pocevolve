import cProfile
import pstats
from pathlib import Path
import traceback

from src.config import *
from src.utils import load_text, load_json, dump_json
from src.pipeline import run_gepa_optimization

def _transcript_succeeded(transcript: dict) -> bool:
    for attempt in transcript.get('attempts', []):
        for prompt in (attempt.get('seed_prompts') or []):
            if prompt.get('exploit_result'):
                return True
    return False


def main():
    print(DATASET_LIST)
    training_data_path = Path(TRAINING_DATA)


    ids = load_text(DATASET_LIST).splitlines()
    for id in ids:
        transcript = {"id": id}
        id = id.replace(":", "_")
        transcript_file = Path(GEPA_LOG_DIR) / id / "transcript.json"


        if transcript_file.exists():
            _transcript = load_json(str(transcript_file))
            if "error" not in _transcript:
                print(f'No error in {id}. Skip.')
                continue
            if _transcript_succeeded(_transcript):
                print(f'Already succeeded in previous evolver run for {id}. Skip.')
                continue
            if "attempts" in _transcript:
                transcript['attempts'] = _transcript['attempts']


        id_data_path = training_data_path / f"{id}.json"
        if not id_data_path.exists():
            print(f'No training input for {id}. Skip.')
            continue


        data = load_json(str(id_data_path)) 
            

        try:
            print(id)
            run_gepa_optimization(data, transcript)
        except KeyboardInterrupt:
            transcript.update({"error": {"message": "KeyboardInterrupt", "trackback": ""}})
        except Exception as e:
            transcript.update({"error": {
                "message": str(e),
                "trackback": traceback.format_exc()
            }})
            print(f"Error during optimization: {str(e)}")
        finally:
            transcript.update({
                "testbed": str(Path(TESTBED_DIR) / id),
                "command_timeout": COMMAND_TIMEOUT,
                "max_iteration": ITERATION,
                "minibatch_size": MINIBATCH_SIZE,
                "model": MODEL_NAME,
                "seed": SEED
            })
            transcript_file = Path(GEPA_LOG_DIR) / id /"transcript.json"
            transcript_file.parent.mkdir(parents=True, exist_ok=True)
            dump_json(transcript, transcript_file)
            

if __name__ == "__main__":

    profiler = cProfile.Profile()
    profiler.enable()

    main()

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("tottime")

    log_file = Path(GEPA_LOG_DIR) / f"profiling_results{DATASET_LIST.replace('/', '.')}"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with open(log_file, "w") as f:
        stats.stream = f
        stats.print_stats()

    print(f"Profiling results written to {log_file}")