"""JSON cache read/write/invalidation."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

class CacheStore:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self.cache_dir / "cache.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self._cache_file.exists():
            try:
                return json.loads(self._cache_file.read_text())
            except (json.JSONDecodeError, OSError):
                return {"version": "1", "entries": {}}
        return {"version": "1", "entries": {}}

    def _save(self) -> None:
        self._cache_file.write_text(json.dumps(self._data, indent=2, default=str))

    def get(self, key: str) -> dict | None:
        entry = self._data.get("entries", {}).get(key)
        return entry

    def put(self, key: str, value: dict) -> None:
        value["cached_at"] = datetime.now(timezone.utc).isoformat() + "Z"
        self._data.setdefault("entries", {})[key] = value
        self._save()

    def invalidate(self, key: str) -> None:
        entries = self._data.get("entries", {})
        if key in entries:
            del entries[key]
            self._save()

    def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all entries whose keys start with prefix."""
        entries = self._data.get("entries", {})
        to_remove = [k for k in entries if k.startswith(prefix)]
        for k in to_remove:
            del entries[k]
        if to_remove:
            self._save()
        return len(to_remove)

    def invalidate_by_category(self, categories: list[str]) -> int:
        """Invalidate all entries matching given categories."""
        entries = self._data.get("entries", {})
        to_remove = []
        for k, v in entries.items():
            if isinstance(v, dict) and v.get("category") in categories:
                to_remove.append(k)
        for k in to_remove:
            del entries[k]
        if to_remove:
            self._save()
        return len(to_remove)

    def clear(self) -> None:
        self._data = {"version": "1", "entries": {}}
        self._save()

    @property
    def size(self) -> int:
        return len(self._data.get("entries", {}))
