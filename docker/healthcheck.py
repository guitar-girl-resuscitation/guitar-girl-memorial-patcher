import json
from entrypoint import CONFIG, health

try:
    health(json.loads(CONFIG.read_text()))
except Exception:
    raise SystemExit(1)
