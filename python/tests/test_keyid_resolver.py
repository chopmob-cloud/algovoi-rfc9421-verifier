"""Sprint B-core: keyid resolver + SSRF guard tests (no real network)."""
from __future__ import annotations

import json

import pytest

from algovoi_rfc9421_verifier.keyid_resolver import (
    KeyResolutionError,
    SSRFError,
    _default_safe_fetch,
    _did_web_to_url,
    _keyid_to_url,
    build_did_document,
    build_key_source,
    check_ip_allowed,
    encode_did_key,
    resolve_keyid,
)

PUB = bytes.fromhex("700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41")
MULTIBASE = encode_did_key(PUB)[len("did:key:"):]  # "z..." form


# --- inline did:key ---

def test_did_key_inline_roundtrip():
    did = encode_did_key(PUB)
    r = resolve_keyid(did)
    assert r.key_source == "inline"
    assert r.public_key == PUB


def test_did_key_rejects_non_ed25519_length():
    with pytest.raises(KeyResolutionError):
        resolve_keyid("did:key:z" + "1" * 5)  # decodes to too-short bytes


# --- did:web URL derivation ---

def test_did_web_host_only():
    assert _did_web_to_url("did:web:api.algovoi.co.uk") == "https://api.algovoi.co.uk/.well-known/did.json"


def test_did_web_with_path():
    assert _did_web_to_url("did:web:example.com:agent:1") == "https://example.com/agent/1/did.json"


def test_unsupported_keyid_scheme_rejected():
    with pytest.raises(KeyResolutionError):
        _keyid_to_url("ftp://example.com/key", allow_did_web=True, allow_https_url=True)


# --- resolver documents (injected fetcher, no network) ---

def _fetcher_returning(payload: dict):
    def _f(url, **kw):
        return json.dumps(payload).encode()
    return _f


def test_resolver_did_json_multibase():
    doc = {"id": "did:web:api.algovoi.co.uk",
           "verificationMethod": [{"type": "Ed25519VerificationKey2020",
                                    "publicKeyMultibase": MULTIBASE}]}
    r = resolve_keyid("did:web:api.algovoi.co.uk", fetcher=_fetcher_returning(doc))
    assert r.key_source == "resolver"
    assert r.public_key == PUB


def test_resolver_1829_address_public_key_hex():
    doc = {"address": "algovoi", "public_key": PUB.hex()}
    r = resolve_keyid("https://envoys.me/keys/agent1", fetcher=_fetcher_returning(doc))
    assert r.key_source == "resolver"
    assert r.public_key == PUB


def test_resolver_jwk_okp():
    import base64
    x = base64.urlsafe_b64encode(PUB).rstrip(b"=").decode()
    doc = {"verificationMethod": [{"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}]}
    r = resolve_keyid("https://example.com/did.json", fetcher=_fetcher_returning(doc))
    assert r.public_key == PUB


def test_resolver_document_without_key_fails():
    with pytest.raises(KeyResolutionError):
        resolve_keyid("https://example.com/x", fetcher=_fetcher_returning({"nope": 1}))


# --- publication helpers round-trip through the resolver ---

def test_build_did_document_roundtrips():
    doc = build_did_document("did:web:api.algovoi.co.uk", PUB)

    def _f(url, **kw):
        return json.dumps(doc).encode()

    r = resolve_keyid("did:web:api.algovoi.co.uk", fetcher=_f)
    assert r.public_key == PUB


def test_build_key_source_roundtrips():
    doc = build_key_source(PUB, address="algovoi")

    def _f(url, **kw):
        return json.dumps(doc).encode()

    r = resolve_keyid("https://envoys.me/keys/agent1", fetcher=_f)
    assert r.public_key == PUB


# --- cache ---

class _DictCache:
    def __init__(self, seed=None):
        self.d = dict(seed or {})
        self.puts = 0

    def get(self, k):
        return self.d.get(k)

    def put(self, k, v):
        self.d[k] = v
        self.puts += 1


def test_cache_hit_skips_fetch():
    cache = _DictCache({"https://example.com/k": PUB})

    def _boom(url, **kw):
        raise AssertionError("fetcher must not be called on a cache hit")

    r = resolve_keyid("https://example.com/k", cache=cache, fetcher=_boom)
    assert r.key_source == "cache"
    assert r.public_key == PUB


def test_cache_populated_on_resolve():
    cache = _DictCache()
    doc = {"public_key": PUB.hex()}
    resolve_keyid("https://example.com/k", cache=cache, fetcher=_fetcher_returning(doc))
    assert cache.puts == 1
    assert cache.d["https://example.com/k"] == PUB


# --- SSRF guard ---

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
    "169.254.169.254",  # cloud metadata
    "::1", "fe80::1", "0.0.0.0", "224.0.0.1",
])
def test_check_ip_allowed_blocks_non_public(ip):
    with pytest.raises(SSRFError):
        check_ip_allowed(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_check_ip_allowed_permits_public(ip):
    check_ip_allowed(ip)  # must not raise


def test_fetch_rejects_non_https_scheme():
    with pytest.raises(SSRFError):
        _default_safe_fetch("http://example.com/k", resolve_host=lambda h: ["8.8.8.8"])


def test_fetch_rejects_private_resolved_ip_before_connect():
    # resolve_host returns a private IP -> blocked before any socket is opened.
    with pytest.raises(SSRFError):
        _default_safe_fetch("https://internal.evil/k", resolve_host=lambda h: ["10.1.2.3"])


def test_fetch_rejects_metadata_ip():
    with pytest.raises(SSRFError):
        _default_safe_fetch("https://rebind.evil/k", resolve_host=lambda h: ["169.254.169.254"])
