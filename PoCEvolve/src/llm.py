from openai import OpenAI
import json
import hashlib
import logging
import time
from pathlib import Path

from src.config import (
	API_BASE,
	API_KEY,
	MODEL_NAME,
	GEPA_LOG_DIR,
	TEMPERATURE,
	MAX_RETRY,
)


llm = OpenAI(
	api_key=API_KEY,
	base_url=API_BASE,
)


def _make_cache_dir() -> Path:
	# place cache next to the logs directory (same parent folder)
	cache_dir = GEPA_LOG_DIR / "cache"
	cache_dir.mkdir(parents=True, exist_ok=True)
	return cache_dir


def _cache_path_for(system_prompt: str, prompt: str, response_format: dict = None) -> Path:
	key = f"model:{MODEL_NAME}\ntemp:{TEMPERATURE}\nsystem:{system_prompt}\nformat:{response_format}\n---\nprompt:{prompt}"
	h = hashlib.sha256(key.encode("utf-8")).hexdigest()
	return _make_cache_dir() / f"{h}.json"


def _strip_think_block(text: str) -> str:
	"""Remove <think>...</think> block emitted by reasoning models before the actual response."""
	import re
	return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).lstrip()


def call_llm(prompt: str, system_prompt: str = "You are a helpful assistant.", response_format: dict = None) -> dict:
	"""Call the configured OpenAI-compatible chat model and return full response data."""
	cache_file = _cache_path_for(system_prompt or "", prompt or "", response_format)

	if cache_file.exists():
		try:
			print('Cache hit:', cache_file)
			with cache_file.open("r", encoding="utf-8") as fh:
				return json.load(fh)
		except Exception:
			pass

	last_exc = None
	for attempt in range(MAX_RETRY):
		try:
			kwargs = {
				"model": MODEL_NAME,
				"messages": [
					{"role": "system", "content": system_prompt},
					{"role": "user", "content": prompt},
				],
				"temperature": TEMPERATURE
			}
			if response_format:
				kwargs["response_format"] = response_format

			response = llm.chat.completions.create(**kwargs)
			break
		except Exception as exc:
			last_exc = exc
			if attempt == 0:
				logging.warning("LLM call failed (%s), retrying in 5s...", exc)
				time.sleep(5)
	else:
		raise last_exc

	data = response.model_dump()
	for choice in data.get("choices", []):
		msg = choice.get("message", {})
		if isinstance(msg.get("content"), str):
			msg["content"] = _strip_think_block(msg["content"])

	try:
		with cache_file.open("w", encoding="utf-8") as fh:
			json.dump(data, fh, ensure_ascii=False, indent=2)
	except Exception:
		pass

	return data