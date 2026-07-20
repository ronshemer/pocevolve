import json

from src.llm import call_llm
from src.prompts import EVOLVE_LLM_SYSTEM_PROMPT


def evolve_prompt(seed_prompt: dict, example_prompts: list):

    example_user_prompts = []
    for prompt in example_prompts:
        user_prompt = prompt.get('userPrompt')
        feedback = prompt.get('feedback')
        text = (
            "**User Prompt**:\n"
            f"{user_prompt}\n"
            "**Feedback**:\n"
            f"{feedback}\n"
        ) 
        example_user_prompts.append(text)

    try:
        context = {
            "seed_prompt": (
                "**User Prompt**:\n"
                f"{seed_prompt.get('userPrompt')}\n"
                "**Feedback**:\n"
                f"{seed_prompt.get('feedback')}\n"
            )  if seed_prompt else "No seed prompt yet. Generate a new one.",
            "example_prompts": example_user_prompts,
        }

        task = "Generate a new user-prompt based on the example user-prompts"

        llm_prompt = (
            f"Task: {task}\n\n"
            f"Context:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
            "Output only the newly generated user prompt text."
        )
        llm_output = call_llm(
            system_prompt=EVOLVE_LLM_SYSTEM_PROMPT,
            prompt=llm_prompt,
        )
        return {
            "reflective_prompt": llm_prompt,
            "response": llm_output["choices"][0]["message"]["content"].strip(),
            "usage_summary": llm_output.get("usage")
        }
    except Exception as e:
        raise RuntimeError("Error occurred while generating new prompt") from e