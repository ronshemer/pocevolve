import time

from src.evaluator import evaluation_and_feedback_function
from src.evolve_prompt import evolve_prompt
from src.llm import call_llm
from src.config import ITERATION, MINIBATCH_SIZE
from src.selector import select_candidate_for_evolve
from src.prompts import REQUIRED_CONTEXTS


def run_gepa_optimization(data: dict, transcript: dict):
    
    prompts_list = data.get("seen_prompts_filtered_k5", []) or [data.get('generated_exploits', [])]
    if len(prompts_list) == 0:
        return

    transcript.setdefault('attempts', [])
    
    exploit_result = False
    
    for index, prompts in enumerate(prompts_list):

        if exploit_result:
            break

        if index < len(transcript['attempts']):
            attempt_transcript = transcript['attempts'][index]
        else:
            attempt_transcript = {
                "attempt_index": index,
                "seed_prompts": [],
                "timers": {}
            }
            transcript['attempts'].append(attempt_transcript)

        attempt_start_time = time.perf_counter()
        iteration = ITERATION
        seed_prompt = attempt_transcript['seed_prompts'][-1] if len(attempt_transcript['seed_prompts']) > 0 else {}

        try:
            if "prompts_w_feedbacks" not in attempt_transcript:
                eval_start = time.perf_counter()
                prompts_w_feedbacks, _ = evaluation_and_feedback_function(prompts, data)
                eval_time = time.perf_counter() - eval_start
                attempt_transcript["prompts_w_feedbacks"] = prompts_w_feedbacks
                attempt_transcript["timers"]["initial_evaluation"] = eval_time
            else:
                prompts_w_feedbacks = attempt_transcript['prompts_w_feedbacks']

            iteration -= len(attempt_transcript['seed_prompts'])
            while True:
                dataset_size = len(prompts_w_feedbacks)
                if dataset_size == 0:
                    attempt_transcript.update({"current_iteration": iteration})
                    break

                seed_id = id(seed_prompt) if seed_prompt else None
                candidate_pool = []
                for idx, p in enumerate(prompts_w_feedbacks):
                    if seed_id and id(p) == seed_id:
                        continue
                    scores_vec = p.get('scores')
                    if not isinstance(scores_vec, list):
                        scores_vec = [0.0] * len(REQUIRED_CONTEXTS)

                    if len(scores_vec) < len(REQUIRED_CONTEXTS):
                        scores_vec = scores_vec + [0.0] * (len(REQUIRED_CONTEXTS) - len(scores_vec))
                    elif len(scores_vec) > len(REQUIRED_CONTEXTS):
                        scores_vec = scores_vec[: len(REQUIRED_CONTEXTS)]

                    avg = p.get('avg_score', sum(scores_vec) / len(scores_vec) if scores_vec else 0.0)

                    candidate_pool.append({
                        'prompt': p,
                        'scores': scores_vec,
                        'avg_score': avg,
                        'index': idx,
                    })

                if not candidate_pool:
                    attempt_transcript.update({"current_iteration": iteration})
                    break

                selected_candidates = select_candidate_for_evolve(
                    candidate_pool,
                    num_tasks=len(REQUIRED_CONTEXTS),
                    num_candidates=MINIBATCH_SIZE,
                )

                minibatch_prompts = [c['prompt'] for c in selected_candidates]
                minibatch_indexes = [c['index'] for c in selected_candidates]

                iteration_timers = {}

                evolve_start = time.perf_counter()
                new_prompt = evolve_prompt(seed_prompt, minibatch_prompts)
                iteration_timers["evolve_prompt"] = time.perf_counter() - evolve_start

                system_prompt = minibatch_prompts[0]['systemPrompt']
                llm_start = time.perf_counter()
                llm_output = call_llm(
                    system_prompt=system_prompt,
                    prompt=new_prompt.get('response'),
                )
                iteration_timers["call_llm"] = time.perf_counter() - llm_start
                
                response = llm_output['choices'][0]['message']['content'].strip()
                usage_summary = llm_output['usage']
                
                seed_prompt = {
                    "reflective_prompt": new_prompt.get('reflective_prompt'),
                    "systemPrompt": system_prompt,
                    "userPrompt": new_prompt.get('response'),
                    "response": response,
                    "llm_usage_summary": usage_summary,
                    "evolve_usage_summary": new_prompt.get('usage_summary'),
                    "minibatch_indexes": minibatch_indexes,
                }
                eval_start = time.perf_counter()
                seed_prompt_list, exploit_result = evaluation_and_feedback_function([seed_prompt], data)
                iteration_timers["evaluation"] = time.perf_counter() - eval_start

                seed_prompt = seed_prompt_list[0]
                # the newly evaluated seed_prompt becomes a candidate for future minibatches
                prompts_w_feedbacks.append(seed_prompt)
                seed_prompt["exploit_result"] = exploit_result
                seed_prompt["iteration_timers"] = iteration_timers
                attempt_transcript["seed_prompts"].append(seed_prompt)

                iteration -= 1
                attempt_transcript.update({"current_iteration": iteration})

                if exploit_result or iteration == 0:
                    break
            attempt_transcript["exploit_result"] = exploit_result
        except Exception:
            raise
        finally:
            attempt_transcript["timers"]["total_attempt_time"] = time.perf_counter() - attempt_start_time