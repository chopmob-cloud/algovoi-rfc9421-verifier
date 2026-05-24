"""
RFC 9421 + RFC 9530 verification top-level.

Two entry points:

- verify_signature(signing_base, signature_bytes, public_key) ->
  VerifyResult.  Lower-level: caller has already built the signing
  base.
- verify_request(method, authority, path, headers, body, public_key)
  -> VerifyResult.  High-level: parses Signature-Input + Signature,
  builds the signing base, verifies the signature and the
  Content-Digest in one call.

This v0.1.0 surface supports Ed25519 only (the substrate's reference
algorithm; aligned with the RFC 8032 Section 7.1 deterministic
keypair used in the algovoi-jcs-conformance-vectors fixture set).
Other JOSE algorithms (ECDSA-P256, RSA-PSS, HMAC) are roadmap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from algovoi_rfc9421_verifier.parse import (
    parse_signature_input,
    parse_signature_value,
    SignatureInputParseError,
)
from algovoi_rfc9421_verifier.signing_base import (
    build_signing_base,
    SigningBaseError,
)
from algovoi_rfc9421_verifier.content_digest import (
    verify_content_digest,
    ContentDigestError,
)


class VerifyError(ValueError):
    """Raised when verification setup is invalid (not when a signature
    fails to verify -- that is captured in VerifyResult.errors)."""


@dataclass
class VerifyResult:
    """Result of an RFC 9421 verification.

    valid is True only if every check ran AND every check passed.
    Specific check outcomes are exposed individually for debugging.
    """

    valid: bool = False
    signature_valid: bool = False
    content_digest_valid: bool = False
    signing_base: str = ""
    covered_components: list[str] = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    label: str = ""
    errors: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> "VerifyResult":
        self.errors.append(msg)
        self.valid = False
        return self


PublicKey = Union[bytes, str]
"""Either raw Ed25519 public-key bytes (32 bytes) or hex-encoded string."""


def _public_key_bytes(public_key: PublicKey) -> bytes:
    if isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise VerifyError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key)}"
            )
        return public_key
    if isinstance(public_key, str):
        key_hex = public_key.removeprefix("0x")
        try:
            kb = bytes.fromhex(key_hex)
        except ValueError as e:
            raise VerifyError(f"public key hex is invalid: {e}") from e
        if len(kb) != 32:
            raise VerifyError(
                f"Ed25519 public key hex must decode to 32 bytes, got {len(kb)}"
            )
        return kb
    raise VerifyError(
        f"public_key must be bytes or hex str, got {type(public_key).__name__}"
    )


def verify_signature(
    signing_base: str,
    signature_bytes: bytes,
    public_key: PublicKey,
    *,
    algorithm: str = "ed25519",
) -> bool:
    """Verify an Ed25519 signature over the signing base.

    Returns True on success. Raises VerifyError on invalid inputs.
    Returns False on signature mismatch.
    """
    if algorithm.lower() != "ed25519":
        raise VerifyError(
            f"v0.1.0 supports ed25519 only; got {algorithm!r}"
        )
    if not isinstance(signing_base, str):
        raise VerifyError(
            f"signing_base must be str, got {type(signing_base).__name__}"
        )
    if not isinstance(signature_bytes, (bytes, bytearray)):
        raise VerifyError(
            f"signature_bytes must be bytes-like, got {type(signature_bytes).__name__}"
        )
    if len(signature_bytes) != 64:
        raise VerifyError(
            f"Ed25519 signature must be 64 bytes, got {len(signature_bytes)}"
        )

    pk_bytes = _public_key_bytes(public_key)

    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError as e:
        raise VerifyError(
            "PyNaCl is required for Ed25519 verification. Install with 'pip install pynacl'."
        ) from e

    verify_key = VerifyKey(pk_bytes)
    try:
        verify_key.verify(
            signing_base.encode("utf-8"), bytes(signature_bytes)
        )
    except BadSignatureError:
        return False
    return True


def verify_request(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    public_key: PublicKey,
    scheme: str = "https",
    require_content_digest: bool = True,
    require_algorithm: str | None = "sha-256",
) -> VerifyResult:
    """High-level verification of an RFC 9421-signed HTTP request.

    Steps:
      1. Locate Signature-Input + Signature headers
      2. Parse Signature-Input -> covered components + parameters
      3. Parse Signature -> signature bytes
      4. (Optional) Verify Content-Digest against the body
      5. Build the signing base from covered components
      6. Verify the Ed25519 signature

    Returns a VerifyResult. All errors land in result.errors;
    result.valid is True iff every check passed.
    """
    result = VerifyResult()

    norm_headers = {k.lower(): v for k, v in headers.items()}

    si_value = norm_headers.get("signature-input")
    if not si_value:
        return result.fail("Signature-Input header missing")
    s_value = norm_headers.get("signature")
    if not s_value:
        return result.fail("Signature header missing")

    try:
        parsed_si = parse_signature_input(si_value)
    except SignatureInputParseError as e:
        return result.fail(f"Signature-Input parse error: {e}")
    result.label = parsed_si.label
    result.covered_components = parsed_si.covered_components
    result.parameters = parsed_si.parameters

    try:
        s_label, sig_bytes = parse_signature_value(s_value)
    except SignatureInputParseError as e:
        return result.fail(f"Signature parse error: {e}")
    # Enforce label match only when both labels are non-empty. The
    # unlabelled forms found in some real-world implementations don't
    # carry labels at all, so any match against an empty label is
    # treated as compatible.
    if (
        s_label
        and parsed_si.label
        and s_label != parsed_si.label
    ):
        return result.fail(
            f"Signature label {s_label!r} does not match Signature-Input label {parsed_si.label!r}"
        )

    if require_content_digest:
        cd_header = norm_headers.get("content-digest")
        if not cd_header:
            return result.fail("Content-Digest header required but missing")
        try:
            verify_content_digest(
                body, cd_header, require_algorithm=require_algorithm
            )
            result.content_digest_valid = True
        except ContentDigestError as e:
            return result.fail(f"Content-Digest verification failed: {e}")
    else:
        result.content_digest_valid = True

    try:
        signing_base = build_signing_base(
            parsed_si.covered_components,
            method=method,
            authority=authority,
            path=path,
            scheme=scheme,
            headers=norm_headers,
            parameters=parsed_si.parameters,
        )
    except SigningBaseError as e:
        return result.fail(f"Signing-base build error: {e}")
    result.signing_base = signing_base

    alg = parsed_si.parameters.get("alg", "ed25519")
    if not isinstance(alg, str):
        return result.fail(
            f"Signature-Input 'alg' parameter must be string, got {type(alg).__name__}"
        )

    try:
        sig_ok = verify_signature(
            signing_base, sig_bytes, public_key, algorithm=alg
        )
    except VerifyError as e:
        return result.fail(f"Signature verification setup error: {e}")
    if not sig_ok:
        return result.fail("Ed25519 signature does not verify against signing base")
    result.signature_valid = True

    result.valid = result.signature_valid and result.content_digest_valid
    return result
