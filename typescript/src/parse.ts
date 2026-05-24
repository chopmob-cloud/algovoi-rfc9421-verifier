/**
 * RFC 9421 Signature-Input and Signature header parsers.
 *
 * Mirror of the Python algovoi_rfc9421_verifier.parse module.
 */

export class SignatureInputParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureInputParseError";
  }
}

export interface ParsedSignatureInput {
  label: string;
  covered_components: string[];
  parameters: Record<string, string | number>;
  raw: string;
}

const LABEL_RE = /^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/;
const COVERED_RE = /\(\s*(?:"[^"]*"\s*)*\)/;
const QUOTED_RE = /"([^"]*)"/g;
const PARAM_RE = /([A-Za-z][A-Za-z0-9_-]*)=([^;,\s]+|"[^"]*")/g;

export function parseSignatureInput(headerValue: string): ParsedSignatureInput {
  if (typeof headerValue !== "string") {
    throw new SignatureInputParseError(
      `header must be string, got ${typeof headerValue}`,
    );
  }
  const trimmed = headerValue.trim();
  if (trimmed.length === 0) {
    throw new SignatureInputParseError("empty header value");
  }

  let label: string;
  let rest: string;

  const labelMatch = LABEL_RE.exec(trimmed);
  if (labelMatch) {
    label = labelMatch[1];
    rest = trimmed.slice(labelMatch[0].length);
  } else if (trimmed.startsWith("(")) {
    label = "";
    rest = trimmed;
  } else {
    throw new SignatureInputParseError(
      `no label or covered-components list found at start: ${JSON.stringify(trimmed.slice(0, 40))}`,
    );
  }

  const coveredMatch = COVERED_RE.exec(rest);
  if (!coveredMatch) {
    throw new SignatureInputParseError("no covered-components list found");
  }
  const coveredRaw = coveredMatch[0];
  const covered: string[] = [];
  let qm: RegExpExecArray | null;
  const localQuoted = /"([^"]*)"/g;
  while ((qm = localQuoted.exec(coveredRaw)) !== null) {
    covered.push(qm[1]);
  }
  rest = rest.slice(coveredMatch.index + coveredRaw.length);

  const parameters: Record<string, string | number> = {};
  const localParam = new RegExp(PARAM_RE.source, "g");
  let pm: RegExpExecArray | null;
  while ((pm = localParam.exec(rest)) !== null) {
    const key = pm[1];
    const raw = pm[2];
    if (raw.startsWith('"') && raw.endsWith('"')) {
      parameters[key] = raw.slice(1, -1);
    } else if (/^-?\d+$/.test(raw)) {
      parameters[key] = parseInt(raw, 10);
    } else {
      parameters[key] = raw;
    }
  }

  return {
    label,
    covered_components: covered,
    parameters,
    raw: trimmed,
  };
}

export function parseSignatureValue(headerValue: string): {
  label: string;
  signature: Uint8Array;
} {
  if (typeof headerValue !== "string") {
    throw new SignatureInputParseError(
      `header must be string, got ${typeof headerValue}`,
    );
  }
  const trimmed = headerValue.trim();
  if (trimmed.length === 0) {
    throw new SignatureInputParseError("empty Signature header value");
  }

  let label: string;
  let rest: string;

  const labelMatch = LABEL_RE.exec(trimmed);
  if (labelMatch) {
    label = labelMatch[1];
    rest = trimmed.slice(labelMatch[0].length).trim();
  } else if (trimmed.startsWith(":")) {
    label = "";
    rest = trimmed;
  } else {
    throw new SignatureInputParseError(
      `no label or signature-value prefix found at start: ${JSON.stringify(trimmed.slice(0, 40))}`,
    );
  }

  if (!rest.startsWith(":") || !rest.endsWith(":")) {
    throw new SignatureInputParseError(
      "signature value must be wrapped in colons (RFC 8941 byte-sequence form)",
    );
  }

  const sigB64 = rest.slice(1, -1);
  let sigBytes: Uint8Array;
  try {
    sigBytes = new Uint8Array(Buffer.from(sigB64, "base64"));
  } catch (e) {
    throw new SignatureInputParseError(
      `signature value is not valid base64: ${(e as Error).message}`,
    );
  }
  return { label, signature: sigBytes };
}
