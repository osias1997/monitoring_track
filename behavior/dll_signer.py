"""
Loaded DLL / module digital signature validation (Authenticode).

Uses PowerShell Get-AuthenticodeSignature with an in-memory cache.
Flags unsigned or untrusted modules as interesting.

Tool made by Osidev
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import behavior_config as cfg


def _ps_signature(path: str) -> dict[str, Any]:
    # Escape single quotes for PowerShell string literal
    safe = path.replace("'", "''")
    cmd = (
        f"$s = Get-AuthenticodeSignature -FilePath '{safe}'; "
        f"[pscustomobject]@{{Status=[string]$s.Status; "
        f"StatusMessage=$s.StatusMessage; "
        f"Signer=($s.SignerCertificate.Subject); "
        f"Issuer=($s.SignerCertificate.Issuer)}} | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return {"Status": "Unknown", "error": (completed.stderr or "")[:200]}
        return json.loads(completed.stdout)
    except Exception as exc:
        return {"Status": "Unknown", "error": str(exc)}


@lru_cache(maxsize=2048)
def verify_signature(path: str) -> dict[str, Any]:
    """Return Authenticode status dict for a file path (cached)."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"Status": "NotFound", "path": path}
    info = _ps_signature(str(p))
    info["path"] = str(p)
    status = str(info.get("Status") or "Unknown")
    info["signed"] = status.lower() == "valid"
    info["suspicious"] = status.lower() in {"notsigned", "hashmismatch", "nottrusted", "unknownerror"}
    return info


def enrich_modules(modules: list[str], limit: int = 40) -> list[dict[str, Any]]:
    """Validate a sample of module paths; prefer non-system locations first."""
    if not cfg.ENABLE_DLL_SIGNATURE_CHECK:
        return [{"path": m, "Status": "Skipped"} for m in modules[:limit]]

    def rank(path: str) -> int:
        lower = path.lower()
        if any(x in lower for x in ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\")):
            return 0
        if "\\windows\\" in lower:
            return 2
        return 1

    ordered = sorted(modules, key=rank)
    out: list[dict[str, Any]] = []
    for path in ordered[:limit]:
        # Skip pure device/section names
        if not path or path.startswith("\\Device\\") or "\\" not in path:
            continue
        if not path.lower().endswith((".dll", ".ocx", ".exe", ".sys")):
            continue
        out.append(verify_signature(path))
    return out


def unsigned_or_untrusted(enriched: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bad = []
    for item in enriched:
        status = str(item.get("Status") or "").lower()
        if cfg.DLL_FLAG_UNSIGNED and status == "notsigned":
            bad.append(item)
        elif cfg.DLL_FLAG_UNTRUSTED and status in {"hashmismatch", "nottrusted"}:
            bad.append(item)
    return bad
