"""Optional, offline-safe MITRE ATT&CK technique-ID existence check.

How it works:
1. ``dforge validate --update-attack-cache`` downloads the Enterprise ATT&CK STIX
   bundle once into the cache directory (network needed only for this step).
2. The bundle is parsed with mitreattack-python and reduced to a small ID index
   (``attack_ids.json``), keyed by the bundle's SHA-256 so it rebuilds only when
   the bundle changes.
3. Later runs read the index only. With no cache present the check is skipped
   (``--attack-check auto``) or fails (``--attack-check require``). It never goes
   to the network on its own.

Cache location: ``$DFORGE_CACHE_DIR`` or ``~/.cache/detectionforge``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

__all__ = [
    "ATTACK_STIX_URL",
    "AttackCatalog",
    "AttackCatalogError",
    "AttackStatus",
    "default_cache_dir",
    "load_catalog",
    "update_cache",
]

# Official MITRE repo for ATT&CK STIX 2.1 data. If MITRE moves this file,
# override with --attack-url.
ATTACK_STIX_URL: Final = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
STIX_FILENAME: Final = "enterprise-attack.json"
INDEX_FILENAME: Final = "attack_ids.json"
INDEX_FORMAT_VERSION: Final = 1
DOWNLOAD_TIMEOUT_S: Final = 120


class AttackCatalogError(RuntimeError):
    """Raised when the ATT&CK cache cannot be built or read."""


class AttackStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"  # deprecated or revoked in ATT&CK
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AttackCatalog:
    active: frozenset[str]
    deprecated: frozenset[str]
    attack_version: str | None

    def status(self, technique_id: str) -> AttackStatus:
        if technique_id in self.active:
            return AttackStatus.ACTIVE
        if technique_id in self.deprecated:
            return AttackStatus.DEPRECATED
        return AttackStatus.UNKNOWN


def default_cache_dir() -> Path:
    env = os.environ.get("DFORGE_CACHE_DIR")
    return Path(env).expanduser() if env else Path.home() / ".cache" / "detectionforge"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _external_id(obj: Any) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _techniques_from_stix(stix_path: Path) -> list[Any]:
    """Return all attack-pattern objects, including revoked/deprecated ones."""
    try:
        from mitreattack.stix20 import MitreAttackData  # noqa: PLC0415 (heavy; lazy-loaded)
    except ImportError as exc:
        raise AttackCatalogError(
            "mitreattack-python is not installed; run `pip install mitreattack-python`"
        ) from exc
    try:
        data = MitreAttackData(str(stix_path))
        techniques: list[Any] = data.get_techniques(remove_revoked_deprecated=False)
    except Exception as exc:  # library raises assorted exception types on bad input
        raise AttackCatalogError(f"could not parse ATT&CK bundle {stix_path}: {exc}") from exc
    return techniques


def _attack_version(stix_path: Path) -> str | None:
    try:
        bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            return str(version) if version is not None else None
    return None


def _build_index(stix_path: Path, index_path: Path) -> AttackCatalog:
    active: set[str] = set()
    deprecated: set[str] = set()
    for technique in _techniques_from_stix(stix_path):
        ext_id = _external_id(technique)
        if ext_id is None:
            continue
        if technique.get("revoked", False) or technique.get("x_mitre_deprecated", False):
            deprecated.add(ext_id)
        else:
            active.add(ext_id)
    # An ID may be revoked in one object and live in another; active wins.
    deprecated -= active
    if not active:
        raise AttackCatalogError(f"no techniques found in {stix_path}; is it an ATT&CK bundle?")

    catalog = AttackCatalog(frozenset(active), frozenset(deprecated), _attack_version(stix_path))
    payload = {
        "format": INDEX_FORMAT_VERSION,
        "source_sha256": _sha256(stix_path),
        "attack_version": catalog.attack_version,
        "active": sorted(active),
        "deprecated": sorted(deprecated),
    }
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return catalog


def load_catalog(cache_dir: Path | None = None) -> AttackCatalog | None:
    """Load the cached catalog. Returns None when nothing is cached. Never uses the network."""
    cache = cache_dir or default_cache_dir()
    stix_path = cache / STIX_FILENAME
    index_path = cache / INDEX_FILENAME

    if index_path.is_file():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            index = None
        if (
            isinstance(index, dict)
            and index.get("format") == INDEX_FORMAT_VERSION
            and (not stix_path.is_file() or index.get("source_sha256") == _sha256(stix_path))
        ):
            return AttackCatalog(
                frozenset(index.get("active", [])),
                frozenset(index.get("deprecated", [])),
                index.get("attack_version"),
            )

    if stix_path.is_file():
        return _build_index(stix_path, index_path)
    return None


def update_cache(cache_dir: Path | None = None, url: str = ATTACK_STIX_URL) -> AttackCatalog:
    """Download the ATT&CK bundle (the only network call) and rebuild the index."""
    if not url.startswith("https://"):
        raise AttackCatalogError(f"refusing non-HTTPS ATT&CK URL: {url}")
    cache = cache_dir or default_cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    stix_path = cache / STIX_FILENAME

    fd, tmp_name = tempfile.mkstemp(dir=cache, suffix=".part")
    tmp_path = Path(tmp_name)
    try:
        with (
            os.fdopen(fd, "wb") as out,
            # https-only enforced above
            urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_S) as resp,  # noqa: S310
        ):
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                out.write(chunk)
        tmp_path.replace(stix_path)
    except OSError as exc:
        raise AttackCatalogError(f"download failed from {url}: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    return _build_index(stix_path, cache / INDEX_FILENAME)