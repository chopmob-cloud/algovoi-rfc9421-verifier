"""
RFC 9421 Section 2.5 signing-base construction.

The signing base is a deterministic byte sequence assembled from the
HTTP message's covered components in the order they appear in the
Signature-Input header's covered-components list.

Each line is:
    "<component-name>": <component-value>
    \n

The component-value is sourced as follows:
- "@method": HTTP method, lowercase
- "@authority": authority component (Host), lowercase
- "@path": URL path component
- "@target-uri": full target URI
- "@scheme": URL scheme, lowercase
- "@status": HTTP status code (response only)
- "created": value of the "created" parameter in Signature-Input
- "expires": value of the "expires" parameter in Signature-Input
- any HTTP header name: the header value as it appears in the message

This v0.1.0 implementation supports the request-side @-components and
header components. Future versions will add response-side components
and the structured-fields-aware variants (sf, bs, key).
"""

from __future__ import annotations


class SigningBaseError(ValueError):
    """Raised when the signing base cannot be constructed."""


def build_signing_base(
    covered_components: list[str],
    *,
    method: str | None = None,
    authority: str | None = None,
    path: str | None = None,
    target_uri: str | None = None,
    scheme: str | None = None,
    status: int | None = None,
    headers: dict[str, str] | None = None,
    parameters: dict[str, str | int] | None = None,
    mode: str = "algovoi-v0",
    signature_params_raw: str | None = None,
) -> str:
    """Build the RFC 9421 signing base.

    covered_components is the ordered list of component names from the
    Signature-Input header.

    The @-derived components and headers are sourced from the keyword
    arguments. parameters carries the Signature-Input parameters
    (created, expires, nonce, etc.) so derived components like
    "created" can resolve.

    mode selects the signing-base shape:
      - "rfc9421": full RFC 9421 §2.5 compliance. @method is preserved
        as-supplied (HTTP convention is uppercase), and a final
        "@signature-params" line is appended carrying signature_params_raw
        verbatim. Required when mode="rfc9421".
      - "algovoi-v0": legacy internal format. @method is lowercased and
        no @signature-params line is appended. Kept for backward
        compatibility with the rfc9421_proxy_chain_v0 conformance fixture
        set signed before v0.2.0.

    signature_params_raw is the post-label portion of the Signature-Input
    header value, i.e. the Inner List + parameters block exactly as it
    appeared on the wire. Required when mode="rfc9421".

    Returns the signing base as a newline-joined string. The bytes for
    Ed25519 signing are this string UTF-8 encoded.
    """
    if mode not in ("algovoi-v0", "rfc9421"):
        raise SigningBaseError(
            f"mode must be 'algovoi-v0' or 'rfc9421', got {mode!r}"
        )
    if mode == "rfc9421" and signature_params_raw is None:
        raise SigningBaseError(
            "rfc9421 mode requires signature_params_raw "
            "(the post-label portion of the Signature-Input header)"
        )
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    parameters = parameters or {}
    lines: list[str] = []

    for component in covered_components:
        value: str
        c = component.lower()

        if c == "@method":
            if method is None:
                raise SigningBaseError("@method covered but method not supplied")
            value = method if mode == "rfc9421" else method.lower()
        elif c == "@authority":
            if authority is None:
                raise SigningBaseError(
                    "@authority covered but authority not supplied"
                )
            value = authority.lower()
        elif c == "@path":
            if path is None:
                raise SigningBaseError("@path covered but path not supplied")
            value = path
        elif c == "@target-uri":
            if target_uri is None:
                raise SigningBaseError(
                    "@target-uri covered but target_uri not supplied"
                )
            value = target_uri
        elif c == "@scheme":
            if scheme is None:
                raise SigningBaseError("@scheme covered but scheme not supplied")
            value = scheme.lower()
        elif c == "@status":
            if status is None:
                raise SigningBaseError("@status covered but status not supplied")
            value = str(status)
        elif c == "created":
            if "created" not in parameters:
                raise SigningBaseError(
                    "'created' covered but no 'created' parameter in Signature-Input"
                )
            value = str(parameters["created"])
        elif c == "expires":
            if "expires" not in parameters:
                raise SigningBaseError(
                    "'expires' covered but no 'expires' parameter in Signature-Input"
                )
            value = str(parameters["expires"])
        elif c.startswith("@"):
            raise SigningBaseError(
                f"unsupported derived component: {component!r}"
            )
        else:
            # Regular header component
            if c not in headers:
                raise SigningBaseError(
                    f"covered header {component!r} not present in supplied headers"
                )
            value = headers[c]

        lines.append(f'"{c}": {value}')

    if mode == "rfc9421":
        lines.append(f'"@signature-params": {signature_params_raw}')

    return "\n".join(lines)
