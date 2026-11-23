from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _windows_account() -> str:
    result = subprocess.run(["whoami"], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def protect_private_directory(path: str | Path, recursive: bool = False) -> None:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        account = _windows_account()
        if recursive:
            subprocess.run(
                ["icacls", str(directory), "/T", "/inheritance:r", "/grant:r", f"{account}:F", "/C"],
                check=True,
                capture_output=True,
                text=True,
            )
        subprocess.run(
            ["icacls", str(directory), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        directory.chmod(0o700)


def protect_private_file(path: str | Path) -> None:
    private_file = Path(path)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(private_file), "/inheritance:r", "/grant:r", f"{_windows_account()}:F"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        private_file.chmod(0o600)
