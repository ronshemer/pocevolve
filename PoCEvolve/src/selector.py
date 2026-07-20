def is_dominated(candidate, others):
    """
    Check if a candidate is dominated by any other candidate.
    """
    for other in others:
        if all(other['scores'][i] >= candidate['scores'][i] for i in range(len(candidate['scores']))) and \
           any(other['scores'][i] > candidate['scores'][i] for i in range(len(candidate['scores']))):
            return True
    return False


def select_candidate_for_evolve(candidate_pool: list, num_tasks: int, num_candidates: int):
    """
    Select up to ``num_candidates`` candidates from the Pareto front.

    The returned candidates are chosen to cover different task dimensions first,
    then the remaining slots are filled with the strongest remaining Pareto
    candidates.
    """
    if not candidate_pool:
        return []

    if len(candidate_pool) <= num_candidates:
        return candidate_pool

    best_scores_per_task = [-1.0] * num_tasks
    for candidate in candidate_pool:
        for i in range(num_tasks):
            if candidate['scores'][i] > best_scores_per_task[i]:
                best_scores_per_task[i] = candidate['scores'][i]

    pareto_candidates = []
    for candidate in candidate_pool:
        others = [other for other in candidate_pool if other != candidate]
        if not is_dominated(candidate, others):
            pareto_candidates.append(candidate)

    if not pareto_candidates:
        pareto_candidates = candidate_pool

    candidate_task_coverage = {}
    for candidate in pareto_candidates:
        candidate_task_coverage[id(candidate)] = {
            i for i in range(num_tasks)
            if abs(candidate['scores'][i] - best_scores_per_task[i]) < 1e-6
        }

    selected_candidates = []
    selected_ids = set()
    covered_tasks = set()

    while len(selected_candidates) < num_candidates:
        best_candidate = None
        best_key = None

        for candidate in pareto_candidates:
            candidate_id = id(candidate)
            if candidate_id in selected_ids:
                continue

            new_task_count = len(candidate_task_coverage[candidate_id] - covered_tasks)
            if new_task_count == 0 and len(selected_candidates) < len(pareto_candidates):
                continue

            key = (
                new_task_count,
                len(candidate_task_coverage[candidate_id]),
                candidate.get('avg_score', sum(candidate['scores']) / len(candidate['scores'])),
            )

            if best_key is None or key > best_key:
                best_candidate = candidate
                best_key = key

        if best_candidate is None:
            break

        selected_candidates.append(best_candidate)
        selected_ids.add(id(best_candidate))
        covered_tasks.update(candidate_task_coverage[id(best_candidate)])

    if len(selected_candidates) < num_candidates:
        remaining_candidates = [
            candidate for candidate in candidate_pool
            if id(candidate) not in selected_ids
        ]
        remaining_candidates.sort(
            key=lambda candidate: (
                candidate.get('avg_score', sum(candidate['scores']) / len(candidate['scores'])),
                sum(abs(candidate['scores'][i] - best_scores_per_task[i]) < 1e-6 for i in range(num_tasks)),
            ),
            reverse=True,
        )
        selected_candidates.extend(remaining_candidates[:num_candidates - len(selected_candidates)])

    return selected_candidates