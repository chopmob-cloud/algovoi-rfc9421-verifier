"""
RFC 9421 Signature-Input and Signature header parsers.

The Signature-Input header carries the covered components and the
signing parameters, in RFC 8941 structured-fields form. Format:

    <label>=("<comp1>" "<comp2>" ...);param1=val1;param2=val2

The Signature header carries the actual signature bytes:

    <label>=:<base64-signature>:

Both headers can carry multiple labels separated by commas. This
parser returns the first label's data for the v0.1.0 surface; the
multi-label case is a v0.2.0 enhancement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class SignatureInputParseError(ValueError):
    """Raised when a Signature-Input header cannot be parsed."""


@dataclass
class ParsedSignatureInput:
    """Parsed Signature-Input header for a single label."""

    label: str
    covered_components: list[str]
    parameters: dict[str, str | int]
    raw: str


_LABEL_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*")
_COVERED_RE = re.compile(r'\(\s*(?:"[^"]*"\s*)*\)')
_QUOTED_RE = re.compile(r'"([^"]*)"')
_PARAM_RE = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)=([^;,\s]+|"[^"]*")')


def parse_signature_input(header_value: str) -> ParsedSignatureInput:
    """Parse a Signature-Input header value.

    Accepts the strict RFC 9421 labelled form:
        sig=("@method" "@authority" "@path" "content-digest" "created");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"

    Also accepts the unlabelled form found in some real-world
    implementations (label defaults to empty string):
        ("@method" "@authority" "@path" "content-digest" "created");created=...

    Returns a ParsedSignatureInput with covered_components and parameters.
    Raises SignatureInputParseError on malformed input.
    """
    if not isinstance(header_value, str):
        raise SignatureInputParseError(
            f"header must be str, got {type(header_value).__name__}"
        )
    header_value = header_value.strip()
    if not header_value:
        raise SignatureInputParseError("empty header value")

    label_match = _LABEL_RE.match(header_value)
    if label_match:
        label = label_match.group(1)
        rest = header_value[label_match.end():]
    elif header_value.startswith("("):
        # Unlabelled form: accept it, set label to empty string.
        label = ""
        rest = header_value

    else:
        raise SignatureInputParseError(
            f"no label or covered-components list found at start: {header_value[:40]!r}"
        )

    covered_match = _COVERED_RE.match(rest)
    if not covered_match:
        raise SignatureInputParseError(
            "no covered-components list found"
        )
    covered_raw = covered_match.group(0)
    covered_components = _QUOTED_RE.findall(covered_raw)
    rest = rest[covered_match.end():]

    parameters: dict[str, str | int] = {}
    # Parameters are separated by ;
    for match in _PARAM_RE.finditer(rest):
        key = match.group(1)
        raw_val = match.group(2)
        if raw_val.startswith('"') and raw_val.endswith('"'):
            parameters[key] = raw_val[1:-1]
        else:
            try:
                parameters[key] = int(raw_val)
            except ValueError:
                parameters[key] = raw_val

    return ParsedSignatureInput(
        label=label,
        covered_components=covered_components,
        parameters=parameters,
        raw=header_value,
    )


def parse_signature_value(header_value: str) -> tuple[str, bytes]:
    """Parse a Signature header value.

    Accepts:
        sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3zFhp0j8cLjmDJvGmySDBAQ==:

    Returns (label, signature_bytes).
    """
    import base64

    if not isinstance(header_value, str):
        raise SignatureInputParseError(
            f"header must be str, got {type(header_value).__name__}"
        )
    header_value = header_value.strip()
    if not header_value:
        raise SignatureInputParseError("empty Signature header value")

    label_match = _LABEL_RE.match(header_value)
    if label_match:
        label = label_match.group(1)
        rest = header_value[label_match.end():].strip()
    elif header_value.startswith(":"):
        # Unlabelled form: accept it, set label to empty string.
        label = ""
        rest = header_value
    else:
        raise SignatureInputParseError(
            f"no label or signature-value prefix found at start: {header_value[:40]!r}"
        )

    if not rest.startswith(":") or not rest.endswith(":"):
        raise SignatureInputParseError(
            "signature value must be wrapped in colons (RFC 8941 byte-sequence form)"
        )
    sig_b64 = rest[1:-1]
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception as e:
        raise SignatureInputParseError(
            f"signature value is not valid base64: {e}"
        ) from e
    return label, sig_bytes
