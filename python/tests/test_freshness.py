"""Sprint A item 1: replay protection (freshness + nonce) tests."""
from __future__ import annotations

import pytest

from algovoi_rfc9421_verifier import FreshnessError, check_freshness, verify_request
from algovoi_rfc9421_signer import DEFAULT_COVERED, sign_request

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
METHOD = "GET"
KEYID = "did:web:api.algovoi.co.uk"
BASE_TIME = 1778955520


def _sign(**kw) -> dict:
    res = sign_request(
        method=METHOD,
        authority=AUTHORITY,
        path=PATH,
        body=b"",
        private_key=SEED_HEX,
        keyid=KEYID,
        **kw,
    )
    return {
        "host": AUTHORITY,
        "content-digest": res.content_digest,
        "signature-input": res.signature_input,
        "signature": res.signature,
    }


def _verify(headers, **kw):
    return verify_request(
        method=METHOD,
        authority=AUTHORITY,
        path=PATH,
        headers=headers,
        body=b"",
        public_key=PUBKEY_HEX,
        **kw,
    )


def test_fresh_created_passes():
    headers = _sign(created=BASE_TIME)
    result = _verify(headers, now=BASE_TIME + 5, max_age_seconds=300)
    assert result.valid is True, result.errors


def test_expired_signature_fails():
    covered = DEFAULT_COVERED + ["expires"]
    headers = _sign(created=BASE_TIME, expires=BASE_TIME + 100, covered_components=covered)
    result = _verify(headers, now=BASE_TIME + 10_000)
    assert result.valid is False
    assert any("expired" in e.lower() for e in result.errors)


def test_future_created_beyond_skew_fails():
    headers = _sign(created=BASE_TIME + 10_000)
    result = _verify(headers, now=BASE_TIME, require_created=True)
    assert result.valid is False
    assert any("future" in e.lower() for e in result.errors)


def test_created_within_skew_passes():
    headers = _sign(created=BASE_TIME + 30)
    result = _verify(headers, now=BASE_TIME, require_created=True, max_skew_seconds=60)
    assert result.valid is True, result.errors


def test_older_than_max_age_fails():
    headers = _sign(created=BASE_TIME)
    result = _verify(headers, now=BASE_TIME + 10_000, max_age_seconds=300)
    assert result.valid is False
    assert any("older" in e.lower() or "age" in e.lower() for e in result.errors)


def test_static_fixture_old_created_passes_when_max_age_off():
    # Library default: max_age_seconds=None -> no age check, so a long-lived
    # static fixture still verifies. This is what keeps proxy_chain_v* valid.
    headers = _sign(created=BASE_TIME)
    result = _verify(headers, now=BASE_TIME + 10_000_000)
    assert result.valid is True, result.errors


def test_expires_present_and_past_fails_even_when_max_age_off():
    covered = DEFAULT_COVERED + ["expires"]
    headers = _sign(created=BASE_TIME, expires=BASE_TIME + 100, covered_components=covered)
    result = _verify(headers, now=BASE_TIME + 10_000)  # max_age off, expires enforced
    assert result.valid is False
    assert any("expired" in e.lower() for e in result.errors)


def test_replayed_nonce_fails():
    headers = _sign(created=BASE_TIME, nonce="nonce-abc")
    seen = _verify(headers, now=BASE_TIME + 5, nonce_seen=lambda n, k: True)
    assert seen.valid is False
    assert any("replay" in e.lower() for e in seen.errors)


def test_fresh_nonce_passes():
    headers = _sign(created=BASE_TIME, nonce="nonce-xyz")
    result = _verify(headers, now=BASE_TIME + 5, nonce_seen=lambda n, k: False)
    assert result.valid is True, result.errors


def test_nonce_store_error_fails_closed():
    headers = _sign(created=BASE_TIME, nonce="nonce-boom")

    def boom(n, k):
        raise RuntimeError("store down")

    result = _verify(headers, now=BASE_TIME + 5, nonce_seen=boom)
    assert result.valid is False
    assert any("store" in e.lower() for e in result.errors)


# --- unit-level check_freshness ---


def test_check_freshness_uncovered_created_rejected_when_required():
    with pytest.raises(FreshnessError):
        check_freshness(
            {"created": BASE_TIME},
            ["@method", "@path"],  # created NOT covered
            now=BASE_TIME,
            require_created=True,
        )


def test_check_freshness_uncovered_expires_rejected():
    with pytest.raises(FreshnessError):
        check_freshness(
            {"expires": BASE_TIME + 100},
            ["@method", "@path"],  # expires NOT covered
            now=BASE_TIME,
        )
