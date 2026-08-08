"""
keyid resolution for RFC 9421 signatures (Sprint B-core).

Resolves the `keyid` on a signature to a raw 32-byte Ed25519 public key, across
three key sources:

- inline   : `did:key:z...` — the key is encoded in the identifier itself; no
             network, so this path is SSRF-safe by construction and is preferred.
- cache    : a caller-supplied cache is consulted before any fetch.
- resolver : an HTTPS GET of the keyid (a `did:web:` DID or a plain https URL),
             accepting both the `{ "address", "public_key" }` shape and a W3C
             did.json (Ed25519VerificationKey2020 / publicKeyMultibase / Jwk).

The resolver path is guarded against SSRF: https only, the resolved addresses are
checked against a non-public blocklist, the actually-connected peer IP is
re-checked after connect (defeating DNS rebind between check and connect),
redirects are re-validated and capped, and the response has size and time caps.

Only the standard library is required. PEM `public_key` values additionally need
the optional `cryptography` package; every other shape is dependency-free.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import unquote, urljoin, urlsplit


class KeyResolutionError(ValueError):
    """Raised when a keyid cannot be resolved to an Ed25519 public key."""


class SSRFError(KeyResolutionError):
    """Raised when a resolver fetch is blocked by the SSRF guard."""


_ED25519_MULTICODEC = b"\xed\x01"  # varint 0xed01 = Ed25519 public key
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass
class ResolvedKey:
    """A resolved Ed25519 public key and where it came from."""

    public_key: bytes  # raw 32-byte Ed25519 public key
    keyid: str
    key_source: str  # "inline" | "cache" | "resolver"
    document: Optional[dict] = None  # the resolver document, when fetched


# --------------------------------------------------------------------------- #
# base58btc + multibase + multicodec
# --------------------------------------------------------------------------- #

def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s.encode("ascii"):
        idx = _B58_ALPHABET.find(ch)
        if idx == -1:
            raise KeyResolutionError(f"invalid base58 character: {chr(ch)!r}")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_pad + body


def _b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = bytearray()
    while num:
        num, rem = divmod(num, 58)
        out.append(_B58_ALPHABET[rem])
    n_pad = len(b) - len(b.lstrip(b"\x00"))
    out.extend(b"1" * n_pad)
    return out[::-1].decode("ascii")


def _strip_multicodec(raw: bytes) -> bytes:
    if len(raw) == 34 and raw[:2] == _ED25519_MULTICODEC:
        return raw[2:]
    if len(raw) == 32:
        return raw
    raise KeyResolutionError(f"unexpected key length after decode: {len(raw)} bytes")


def _multibase_to_key(mb: str) -> bytes:
    if not mb.startswith("z"):
        raise KeyResolutionError("only base58btc multibase ('z...') is supported")
    return _strip_multicodec(_b58decode(mb[1:]))


def encode_did_key(public_key: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key as a `did:key:z...` identifier.

    Also usable by the key-publication helper. Round-trips with resolve_keyid.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise KeyResolutionError("public_key must be 32 raw Ed25519 bytes")
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + bytes(public_key))


# --------------------------------------------------------------------------- #
# key-publication helpers (B-core: the inverse of resolution)
# --------------------------------------------------------------------------- #

def ed25519_multibase(public_key: bytes) -> str:
    """`z...` publicKeyMultibase for a raw 32-byte Ed25519 public key."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise KeyResolutionError("public_key must be 32 raw Ed25519 bytes")
    return "z" + _b58encode(_ED25519_MULTICODEC + bytes(public_key))


def build_did_document(did_id: str, public_key: bytes, *, controller: Optional[str] = None) -> dict:
    """Build a minimal W3C did.json for an Ed25519 key (served at the did:web URL)."""
    vm_id = f"{did_id}#key-1"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did_id,
        "verificationMethod": [{
            "id": vm_id,
            "type": "Ed25519VerificationKey2020",
            "controller": controller or did_id,
            "publicKeyMultibase": ed25519_multibase(public_key),
        }],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


def build_key_source(public_key: bytes, *, address: str = "") -> dict:
    """Build the minimal `{ address, public_key }` document (the #1829 shape)."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise KeyResolutionError("public_key must be 32 raw Ed25519 bytes")
    return {"address": address, "public_key": bytes(public_key).hex()}


# --------------------------------------------------------------------------- #
# key-string / document extraction
# --------------------------------------------------------------------------- #

def _coerce_key_string(s: str) -> bytes:
    s = s.strip()
    if s.startswith("-----BEGIN"):
        return _pem_ed25519(s)
    if s.startswith("z"):
        return _multibase_to_key(s)
    hexs = s[2:] if s.startswith("0x") else s
    try:
        b = bytes.fromhex(hexs)
        if len(b) == 32:
            return b
    except ValueError:
        pass
    try:
        b = base64.b64decode(s, validate=True)
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise KeyResolutionError("could not decode public_key to 32 Ed25519 bytes")


def _pem_ed25519(pem: str) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )
    except ImportError as exc:
        raise KeyResolutionError(
            "PEM public_key requires the optional 'cryptography' package"
        ) from exc
    key = load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise KeyResolutionError("PEM public_key is not an Ed25519 key")
    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _extract_public_key(doc: dict) -> bytes:
    if not isinstance(doc, dict):
        raise KeyResolutionError("resolver document is not a JSON object")
    pk = doc.get("public_key")
    if isinstance(pk, str):
        return _coerce_key_string(pk)
    vms = doc.get("verificationMethod")
    if isinstance(vms, list):
        for vm in vms:
            if not isinstance(vm, dict):
                continue
            if isinstance(vm.get("publicKeyMultibase"), str):
                return _multibase_to_key(vm["publicKeyMultibase"])
            if isinstance(vm.get("publicKeyHex"), str):
                return _coerce_key_string(vm["publicKeyHex"])
            if isinstance(vm.get("publicKeyBase58"), str):
                return _strip_multicodec(_b58decode(vm["publicKeyBase58"]))
            jwk = vm.get("publicKeyJwk")
            if (
                isinstance(jwk, dict)
                and jwk.get("kty") == "OKP"
                and jwk.get("crv") == "Ed25519"
                and isinstance(jwk.get("x"), str)
            ):
                x = jwk["x"]
                pad = "=" * (-len(x) % 4)
                return base64.urlsafe_b64decode(x + pad)
    raise KeyResolutionError("no Ed25519 public key found in resolver document")


# --------------------------------------------------------------------------- #
# keyid -> URL
# --------------------------------------------------------------------------- #

def _did_web_to_url(did: str) -> str:
    rest = did[len("did:web:"):]
    parts = rest.split(":")
    host = unquote(parts[0])
    if len(parts) == 1:
        path = "/.well-known/did.json"
    else:
        path = "/" + "/".join(unquote(p) for p in parts[1:]) + "/did.json"
    return f"https://{host}{path}"


def _keyid_to_url(keyid: str, *, allow_did_web: bool, allow_https_url: bool) -> str:
    if keyid.startswith("did:web:"):
        if not allow_did_web:
            raise KeyResolutionError("did:web resolution is disabled")
        return _did_web_to_url(keyid)
    if keyid.startswith("https://"):
        if not allow_https_url:
            raise KeyResolutionError("https keyid resolution is disabled")
        return keyid
    raise KeyResolutionError(f"keyid is not resolvable over https: {keyid!r}")


# --------------------------------------------------------------------------- #
# SSRF-guarded fetch
# --------------------------------------------------------------------------- #

def _default_resolve(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, None)]


def check_ip_allowed(ip: str) -> None:
    """Raise SSRFError if `ip` is not a public unicast address."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SSRFError(f"unparseable address: {ip!r}") from exc
    if (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local  # covers 169.254.0.0/16 and fe80::/10
        or obj.is_multicast
        or obj.is_reserved
        or obj.is_unspecified
    ):
        raise SSRFError(f"blocked non-public address: {ip}")
    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped is not None:
        check_ip_allowed(str(obj.ipv4_mapped))


def _default_safe_fetch(
    url: str,
    *,
    resolve_host: Optional[Callable[[str], list]] = None,
    max_bytes: int = 65536,
    timeout: float = 5.0,
    max_redirects: int = 2,
) -> bytes:
    import http.client

    resolve = resolve_host or _default_resolve
    current = url
    redirects = 0
    while True:
        parts = urlsplit(current)
        if parts.scheme != "https":
            raise SSRFError(f"only https is allowed, got scheme {parts.scheme!r}")
        host = parts.hostname
        if not host:
            raise SSRFError("keyid URL has no host")
        port = parts.port or 443
        ips = resolve(host)
        if not ips:
            raise SSRFError(f"no addresses resolved for {host}")
        for ip in ips:
            check_ip_allowed(ip)
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )
        try:
            conn.connect()
            # Re-check the ACTUAL connected peer IP: defeats a DNS rebind between
            # the resolve() check above and the real connect.
            check_ip_allowed(conn.sock.getpeername()[0])
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            conn.request(
                "GET", path,
                headers={"Host": host, "Accept": "application/json, application/did+json"},
            )
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                resp.read()
                if redirects >= max_redirects:
                    raise SSRFError("too many redirects")
                if not loc:
                    raise SSRFError("redirect without Location")
                current = urljoin(current, loc)
                redirects += 1
                continue
            if resp.status != 200:
                raise KeyResolutionError(f"resolver returned HTTP {resp.status}")
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise KeyResolutionError("resolver response exceeds size cap")
            return data
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #

def resolve_keyid(
    keyid: str,
    *,
    cache=None,
    fetcher: Optional[Callable[..., bytes]] = None,
    allow_did_web: bool = True,
    allow_https_url: bool = True,
    resolve_host: Optional[Callable[[str], list]] = None,
    max_bytes: int = 65536,
    timeout: float = 5.0,
    max_redirects: int = 2,
) -> ResolvedKey:
    """Resolve `keyid` to a `ResolvedKey`.

    cache: optional object exposing ``get(keyid) -> key|None`` and
        ``put(keyid, key)``; ``key`` may be raw 32 bytes, hex, or multibase.
    fetcher: optional ``fetch(url, *, resolve_host, max_bytes, timeout,
        max_redirects) -> bytes`` override (for tests or a custom client); the
        default is the SSRF-guarded stdlib fetch.
    """
    if not isinstance(keyid, str) or not keyid:
        raise KeyResolutionError("keyid must be a non-empty string")

    if keyid.startswith("did:key:"):
        mb = keyid[len("did:key:"):]
        return ResolvedKey(_multibase_to_key(mb), keyid, "inline")

    if cache is not None:
        cached = cache.get(keyid)
        if cached is not None:
            key = cached if isinstance(cached, (bytes, bytearray)) else _coerce_key_string(cached)
            return ResolvedKey(bytes(key), keyid, "cache")

    url = _keyid_to_url(keyid, allow_did_web=allow_did_web, allow_https_url=allow_https_url)
    fetch = fetcher or _default_safe_fetch
    body = fetch(
        url,
        resolve_host=resolve_host,
        max_bytes=max_bytes,
        timeout=timeout,
        max_redirects=max_redirects,
    )
    doc = json.loads(body)
    pub = _extract_public_key(doc)
    if cache is not None:
        cache.put(keyid, pub)
    return ResolvedKey(pub, keyid, "resolver", document=doc)


__all__ = [
    "KeyResolutionError",
    "SSRFError",
    "ResolvedKey",
    "resolve_keyid",
    "encode_did_key",
    "ed25519_multibase",
    "build_did_document",
    "build_key_source",
    "check_ip_allowed",
]
