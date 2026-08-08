"""
RFC 9421 signature freshness and replay checks (Sprint A, item 1).

RFC 9421 defines time-based signature parameters (`created`, `expires`) and a
per-message `nonce`, but a verifier that reconstructs the signing base and checks
the signature says nothing about *when* the signature was made. A captured, still
well-formed signature verifies forever unless the verifier also enforces
freshness. This module supplies that check.

Trust rule: only *covered* (signed) `created` / `expires` values are honoured. An
unsigned timestamp is attacker-controlled, so using it to judge freshness would be
worse than useless. A freshness requirement against an uncovered parameter fails
closed, mirroring the content-digest-must-be-covered rule in `verify_request`.

The nonce single-use check lives in `verify_request`, not here, because it needs a
caller-supplied store callback; this module stays pure and stateless.
"""

from __future__ import annotations

from typing import Iterable


class FreshnessError(ValueError):
    """Raised when a signature is stale, not yet valid, expired, or malformed
    in its time parameters."""


def _covered_names(covered_components: Iterable[str]) -> set[str]:
    """Normalise covered-component identifiers to bare lowercase names.

    Tolerates quoting and (forward-compatible with item 4) any ``;`` component
    parameters, taking the name before the first ``;``.
    """
    names: set[str] = set()
    for component in covered_components:
        name = str(component).strip().strip('"')
        name = name.split(";", 1)[0].strip().strip('"').lower()
        if name:
            names.add(name)
    return names


def check_freshness(
    parameters: dict,
    covered_components: Iterable[str],
    *,
    now: int,
    max_age_seconds: int | None = None,
    max_skew_seconds: int = 60,
    enforce_expires: bool = True,
    require_created: bool = False,
    params_signed: bool = True,
) -> None:
    """Validate the time-based signature parameters. No-op when nothing to check.

    Args:
        parameters: parsed Signature-Input parameters (``created``, ``expires``...).
        covered_components: the covered-component list from Signature-Input; only
            names present here are treated as signed and therefore trustworthy.
        now: current unix time in seconds (injected so verification is
            deterministic in tests and against static fixtures).
        max_age_seconds: reject when ``created`` is older than this. ``None``
            disables the age check (the library default; callers such as the
            gateway opt in with a concrete window).
        max_skew_seconds: tolerance for clock skew on both the future-``created``
            and past-``expires`` bounds.
        enforce_expires: when True, a covered ``expires`` in the past is rejected.
        require_created: when True, a signed ``created`` must be present even if
            ``max_age_seconds`` is None.
        params_signed: whether the Signature-Input parameters are themselves
            signed. True in RFC 9421 mode, where ``@signature-params`` (carrying
            ``created`` / ``expires``) is part of the signing base, so a param is
            trustworthy even when it is not also listed as a covered component.
            False for legacy modes without a signed ``@signature-params`` line,
            where only covered components are trusted.

    Raises:
        FreshnessError: on a stale, future, expired, or malformed signature, or
            when freshness is required but the relevant value is not signed.
    """
    covered = _covered_names(covered_components)
    created = parameters.get("created")
    expires = parameters.get("expires")

    def _signed(name: str) -> bool:
        # Trustworthy for freshness iff the value is signed: either a covered
        # component, or (rfc9421 mode) carried in the signed @signature-params.
        return name in covered or params_signed

    if max_age_seconds is not None or require_created:
        if created is None:
            raise FreshnessError(
                "freshness required but no 'created' parameter present"
            )
        if not _signed("created"):
            raise FreshnessError(
                "freshness required but 'created' is not signed "
                "(not a covered component and params are unsigned)"
            )
        created_i = _as_int(created, "created")
        if created_i > now + max_skew_seconds:
            raise FreshnessError(
                "signature 'created' is in the future beyond the allowed skew"
            )
        if max_age_seconds is not None and created_i < now - max_age_seconds:
            raise FreshnessError(
                "signature is older than the maximum allowed age"
            )

    if enforce_expires and expires is not None:
        # A present-but-unsigned expiry is attacker-mutable; refusing to guess is
        # the fail-closed choice, consistent with the content-digest coverage rule.
        if not _signed("expires"):
            raise FreshnessError(
                "'expires' present but not signed "
                "(not a covered component and params are unsigned)"
            )
        expires_i = _as_int(expires, "expires")
        if now > expires_i + max_skew_seconds:
            raise FreshnessError("signature has expired")


def _as_int(value, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise FreshnessError(f"'{name}' is not an integer: {value!r}") from exc


__all__ = ["FreshnessError", "check_freshness"]
