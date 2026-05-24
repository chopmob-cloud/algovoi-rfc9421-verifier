/**
 * RFC 9421 Section 2.5 signing-base construction.
 *
 * Mirror of the Python algovoi_rfc9421_verifier.signing_base module.
 */

export class SigningBaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigningBaseError";
  }
}

export interface SigningBaseInput {
  coveredComponents: string[];
  method?: string;
  authority?: string;
  path?: string;
  targetUri?: string;
  scheme?: string;
  status?: number;
  headers?: Record<string, string>;
  parameters?: Record<string, string | number>;
}

export function buildSigningBase(input: SigningBaseInput): string {
  const normHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    normHeaders[k.toLowerCase()] = v;
  }
  const parameters = input.parameters ?? {};
  const lines: string[] = [];

  for (const component of input.coveredComponents) {
    const c = component.toLowerCase();
    let value: string;

    switch (c) {
      case "@method":
        if (input.method === undefined)
          throw new SigningBaseError("@method covered but method not supplied");
        value = input.method.toLowerCase();
        break;
      case "@authority":
        if (input.authority === undefined)
          throw new SigningBaseError("@authority covered but authority not supplied");
        value = input.authority.toLowerCase();
        break;
      case "@path":
        if (input.path === undefined)
          throw new SigningBaseError("@path covered but path not supplied");
        value = input.path;
        break;
      case "@target-uri":
        if (input.targetUri === undefined)
          throw new SigningBaseError("@target-uri covered but targetUri not supplied");
        value = input.targetUri;
        break;
      case "@scheme":
        if (input.scheme === undefined)
          throw new SigningBaseError("@scheme covered but scheme not supplied");
        value = input.scheme.toLowerCase();
        break;
      case "@status":
        if (input.status === undefined)
          throw new SigningBaseError("@status covered but status not supplied");
        value = String(input.status);
        break;
      case "created":
        if (!("created" in parameters))
          throw new SigningBaseError(
            "'created' covered but no 'created' parameter in Signature-Input",
          );
        value = String(parameters["created"]);
        break;
      case "expires":
        if (!("expires" in parameters))
          throw new SigningBaseError(
            "'expires' covered but no 'expires' parameter in Signature-Input",
          );
        value = String(parameters["expires"]);
        break;
      default:
        if (c.startsWith("@")) {
          throw new SigningBaseError(`unsupported derived component: ${component}`);
        }
        if (!(c in normHeaders)) {
          throw new SigningBaseError(
            `covered header ${JSON.stringify(component)} not present in supplied headers`,
          );
        }
        value = normHeaders[c];
        break;
    }

    lines.push(`"${c}": ${value}`);
  }

  return lines.join("\n");
}
