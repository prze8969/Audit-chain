import hashlib
import json
import os
import time
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

_last_call_time = 0.0


def _get_client() -> OpenAI:
    base_url = os.getenv('LLM_BASE_URL', 'https://api.groq.com/openai/v1')
    api_key = os.getenv('LLM_API_KEY') or os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY', 'dummy')
    return OpenAI(base_url=base_url, api_key=api_key, timeout=60.0)


def _compute_cache_key(model: str, messages: list, tools: list | None) -> str:
    payload = json.dumps({'model': model, 'messages': messages, 'tools': tools}, sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def chat(messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 1200) -> dict:
    global _last_call_time

    model = os.getenv('AGENT_MODEL', 'qwen/qwen3.8-27b')
    min_interval = float(os.getenv('LLM_MIN_INTERVAL', '2.5'))
    cache_enabled = os.getenv('LLM_CACHE', '1') != '0'

    cache_dir = Path('reports/llm_cache')
    cache_key = _compute_cache_key(model, messages, tools)
    cache_file = cache_dir / f'{cache_key}.json'

    if cache_enabled and cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding='utf-8'))
        except Exception:
            pass

    client = _get_client()
    backoff_delays = [4.0, 8.0, 16.0, 32.0, 64.0]
    retries = 0

    while True:
        elapsed_since_last = time.time() - _last_call_time
        if elapsed_since_last < min_interval:
            time.sleep(min_interval - elapsed_since_last)

        start_time = time.time()
        _last_call_time = start_time

        prompt_chars = sum(len(str(m.get('content', ''))) for m in messages)
        if tools:
            prompt_chars += len(json.dumps(tools))

        try:
            kwargs = {
                'model': model,
                'messages': messages,
                'temperature': 0,
                'max_tokens': max_tokens,
            }
            if tools:
                kwargs['tools'] = tools

            resp = client.chat.completions.create(**kwargs)
            duration = time.time() - start_time

            choice = resp.choices[0]
            msg = choice.message
            tool_calls_data = None
            if msg.tool_calls:
                tool_calls_data = [
                    {
                        'id': tc.id,
                        'type': tc.type,
                        'function': {
                            'name': tc.function.name,
                            'arguments': tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]

            result_dict = {
                'content': msg.content,
                'tool_calls': tool_calls_data,
                'role': msg.role,
            }

            if cache_enabled:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(result_dict, indent=2), encoding='utf-8')

            calls_log = Path('reports/llm_calls.jsonl')
            calls_log.parent.mkdir(parents=True, exist_ok=True)
            with calls_log.open('a', encoding='utf-8') as f:
                f.write(json.dumps({'seconds': round(duration, 3), 'prompt_chars': prompt_chars, 'retries': retries}) + '\n')

            return result_dict

        except Exception as e:
            err_str = str(e)
            is_rate_limit = '429' in err_str or 'rate' in err_str.lower()
            is_server_err = any(code in err_str for code in ['500', '502', '503', '504'])
            is_timeout = 'timeout' in err_str.lower()

            if (is_rate_limit or is_server_err or is_timeout) and retries < 5:
                wait_time = backoff_delays[retries]
                if hasattr(e, 'response') and e.response is not None:
                    retry_after = e.response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            wait_time = float(retry_after)
                        except Exception:
                            pass
                retries += 1
                time.sleep(wait_time)
            else:
                raise e
