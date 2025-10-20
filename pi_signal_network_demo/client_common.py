import os, json, base64, httpx, pathlib, time, hashlib
from typing import Optional, Tuple

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
STATE_DIR = pathlib.Path(os.environ.get("STATE_DIR", "state"))
STATE_DIR.mkdir(exist_ok=True)

def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

def post(path: str, json_body: dict):
    url = f"{SERVER_URL}{path}"
    r = httpx.post(url, json=json_body, timeout=10)
    r.raise_for_status()
    return r.json()

def get(path: str, params: dict = None):
    url = f"{SERVER_URL}{path}"
    r = httpx.get(url, params=params or {}, timeout=10)
    r.raise_for_status()
    return r.json()

def log(device: str, msg: str):
    fn = STATE_DIR / f"{device}.log"
    with open(fn, "a") as f: f.write(msg + "\n")
    print(msg)

def save_json(device: str, name: str, obj: dict):
    fn = STATE_DIR / f"{device}_{name}.json"
    fn.write_text(json.dumps(obj, indent=2))

def load_json(device: str, name: str) -> Optional[dict]:
    fn = STATE_DIR / f"{device}_{name}.json"
    return json.loads(fn.read_text()) if fn.exists() else None

def safety_fingerprint(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()
