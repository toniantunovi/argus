"""Tests for cache store."""
import json
from pathlib import Path

import pytest

from argus.cache.store import CacheStore


class TestPutGet:
    def test_put_and_get(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("key1", {"data": "value1"})
        result = store.get("key1")
        assert result is not None
        assert result["data"] == "value1"

    def test_get_nonexistent(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        assert store.get("nonexistent") is None

    def test_put_adds_cached_at(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("key1", {"data": "test"})
        result = store.get("key1")
        assert "cached_at" in result
        assert result["cached_at"].endswith("Z")

    def test_overwrite_existing(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("key1", {"v": 1})
        store.put("key1", {"v": 2})
        assert store.get("key1")["v"] == 2

    def test_size(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        assert store.size == 0
        store.put("a", {"x": 1})
        store.put("b", {"x": 2})
        assert store.size == 2


class TestInvalidate:
    def test_invalidate_existing(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("key1", {"data": "value"})
        store.invalidate("key1")
        assert store.get("key1") is None

    def test_invalidate_nonexistent(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        # Should not raise
        store.invalidate("nonexistent")

    def test_invalidate_by_prefix(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("hyp:func1", {"data": "a"})
        store.put("hyp:func2", {"data": "b"})
        store.put("triage:func1", {"data": "c"})
        removed = store.invalidate_by_prefix("hyp:")
        assert removed == 2
        assert store.get("hyp:func1") is None
        assert store.get("triage:func1") is not None


class TestInvalidateByCategory:
    def test_invalidate_by_category(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("k1", {"category": "auth", "data": "a"})
        store.put("k2", {"category": "auth", "data": "b"})
        store.put("k3", {"category": "injection", "data": "c"})
        removed = store.invalidate_by_category(["auth"])
        assert removed == 2
        assert store.get("k1") is None
        assert store.get("k2") is None
        assert store.get("k3") is not None

    def test_invalidate_multiple_categories(self, tmp_path):
        store = CacheStore(tmp_path / "cache")
        store.put("k1", {"category": "auth"})
        store.put("k2", {"category": "injection"})
        store.put("k3", {"category": "memory"})
        removed = store.invalidate_by_category(["auth", "injection"])
        assert removed == 2
        assert store.size == 1


class TestPersistence:
    def test_write_reload_read(self, tmp_path):
        cache_dir = tmp_path / "cache"
        store1 = CacheStore(cache_dir)
        store1.put("persistent_key", {"data": "survives_reload"})

        # Create a new CacheStore instance from the same directory
        store2 = CacheStore(cache_dir)
        result = store2.get("persistent_key")
        assert result is not None
        assert result["data"] == "survives_reload"

    def test_clear_and_reload(self, tmp_path):
        cache_dir = tmp_path / "cache"
        store1 = CacheStore(cache_dir)
        store1.put("key1", {"data": "x"})
        store1.clear()

        store2 = CacheStore(cache_dir)
        assert store2.get("key1") is None
        assert store2.size == 0

    def test_cache_file_is_valid_json(self, tmp_path):
        cache_dir = tmp_path / "cache"
        store = CacheStore(cache_dir)
        store.put("key1", {"data": "test"})
        cache_file = cache_dir / "cache.json"
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert "version" in data
        assert "entries" in data
