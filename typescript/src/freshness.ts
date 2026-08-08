/**
 * RFC 9421 signature freshness and replay checks (Sprint A, item 1).
 *
 * Mirror of the Python algovoi_rfc9421_verifier.freshness module.
 *
 * RFC 9421 defines time-based signature parameters (`created`, `expires`) and a
 * per-message `nonce`, but a verifier that reconstructs the signing base and
 * checks the signature says nothing about *when* the signature was made. A
 * captured, still well-formed signature verifies forever unless the verifier
 * also enforces freshness. This module supplies that check.
 *
 * Trust rule: only *covered* (signed) `created` / `expires` values are honoured.
 * An unsigned timestamp is attacker-controlled, so using it to judge freshness
 * would be worse than useless. A freshness requirement against an uncovered
 * parameter fails closed, mirroring the content-digest-must-be-covered rule in
 * `verifyRequest`.
 *
 * The nonce single-use check lives in `verifyRequest`, not here, because it
 * needs a caller-supplied store callback; this module stays pure and stateless.
 *
 * All times are unix seconds (numbers).
 */

export class FreshnessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FreshnessError";
  }
}

export interface CheckFreshnessOptions {
  /** current unix time in seconds (injected so verification is deterministic). */
  now: number;
  /**
   * reject when `created` is older than this. `null`/`undefined` disables the
   * age check (the library default; callers opt in with a concrete window).
   */
  maxAgeSeconds?: number | null;
  /** tolerance for clock skew on both future-created and past-expires bounds. */
  maxSkewSeconds?: number;
  /** when true, a covered `expires` in the past is rejected. */
  enforceExpires?: boolean;
  /**
   * when true, a signed `created` must be present even if maxAgeSeconds is
   * null.
   */
  requireCreated?: boolean;
  /**
   * whether the Signature-Input parameters are themselves signed. True in
   * RFC 9421 mode, where `@signature-params` (carrying `created` / `expires`)
   * is part of the signing base, so a param is trustworthy even when it is not
   * also listed as a covered component. False for legacy modes without a signed
   * `@signature-params` line, where only covered components are trusted.
   * Defaults to true.
   */
  paramsSigned?: boolean;
}

function coveredNames(coveredComponents: Iterable<string>): Set<string> {
  const names = new Set<string>();
  for (const component of coveredComponents) {
    let name = String(component).trim();
    if (name.startsWith('"') && name.endsWith('"')) {
      name = name.slice(1, -1);
    } else {
      name = name.replace(/^"+|"+$/g, "");
    }
    name = name.split(";", 1)[0].trim().replace(/^"+|"+$/g, "").toLowerCase();
    if (name) {
      names.add(name);
    }
  }
  return names;
}

function asInt(value: unknown, name: string): number {
  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^-?\d+$/.test(value.trim())
        ? parseInt(value.trim(), 10)
        : NaN;
  if (!Number.isFinite(n)) {
    throw new FreshnessError(`'${name}' is not an integer: ${JSON.stringify(value)}`);
  }
  return n;
}

/**
 * Validate the time-based signature parameters. No-op when nothing to check.
 *
 * @param parameters parsed Signature-Input parameters (`created`, `expires`...).
 * @param coveredComponents the covered-component list from Signature-Input;
 *   only names present here are treated as signed and therefore trustworthy.
 * @param options freshness policy (see {@link CheckFreshnessOptions}).
 *
 * @throws FreshnessError on a stale, future, expired, or malformed signature,
 *   or when freshness is required but the relevant parameter is not covered.
 */
export function checkFreshness(
  parameters: Record<string, string | number>,
  coveredComponents: Iterable<string>,
  options: CheckFreshnessOptions,
): void {
  const now = options.now;
  const maxAgeSeconds =
    options.maxAgeSeconds === undefined ? null : options.maxAgeSeconds;
  const maxSkewSeconds =
    options.maxSkewSeconds === undefined ? 60 : options.maxSkewSeconds;
  const enforceExpires =
    options.enforceExpires === undefined ? true : options.enforceExpires;
  const requireCreated =
    options.requireCreated === undefined ? false : options.requireCreated;
  const paramsSigned =
    options.paramsSigned === undefined ? true : options.paramsSigned;

  const covered = coveredNames(coveredComponents);
  const created =
    "created" in parameters ? parameters["created"] : undefined;
  const expires =
    "expires" in parameters ? parameters["expires"] : undefined;

  // Trustworthy for freshness iff the value is signed: either a covered
  // component, or (rfc9421 mode) carried in the signed @signature-params.
  const signed = (name: string): boolean => covered.has(name) || paramsSigned;

  if (maxAgeSeconds !== null || requireCreated) {
    if (created === undefined || created === null) {
      throw new FreshnessError(
        "freshness required but no 'created' parameter present",
      );
    }
    if (!signed("created")) {
      throw new FreshnessError(
        "freshness required but 'created' is not signed " +
          "(not a covered component and params are unsigned)",
      );
    }
    const createdI = asInt(created, "created");
    if (createdI > now + maxSkewSeconds) {
      throw new FreshnessError(
        "signature 'created' is in the future beyond the allowed skew",
      );
    }
    if (maxAgeSeconds !== null && createdI < now - maxAgeSeconds) {
      throw new FreshnessError(
        "signature is older than the maximum allowed age",
      );
    }
  }

  if (enforceExpires && expires !== undefined && expires !== null) {
    // A present-but-unsigned expiry is attacker-mutable; refusing to guess is
    // the fail-closed choice, consistent with the content-digest coverage rule.
    if (!signed("expires")) {
      throw new FreshnessError(
        "'expires' present but not signed " +
          "(not a covered component and params are unsigned)",
      );
    }
    const expiresI = asInt(expires, "expires");
    if (now > expiresI + maxSkewSeconds) {
      throw new FreshnessError("signature has expired");
    }
  }
}
