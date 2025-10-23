from pathlib import Path as _Path


BASE_URL = "http://10.100.52.65"
PORT = 20_930
URL = f"{BASE_URL}:{PORT}"

FLAG_REGEX = r"The flag \d{2} is : ([a-f0-9]+)"

TIMEOUT = 10.0

ROOT = _Path(__file__).parent.resolve()
SUPPORT = ROOT / "support"
