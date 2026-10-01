import { base64url } from "jose";
import "cbor2/types";
import { validateIssuerAuth } from "./issuerAuth";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { issuerSignedSchema } from "./schemas/issuerSignedSchema";
import { parseSchema } from "./parseSchema";
import { validateNamespaces } from "./nameSpaces";
import { decodeCbor } from "./decodeCbor";

/**
 * Validates a base64url-encoded mdoc credential string.
 *
 * Resolves if the credential is valid. If validation fails, throws an
 * {@link MdocValidationError} describing the failure; it does not return a
 * boolean.
 *
 * @param credential - Base64url-encoded credential.
 * @returns A promise that resolves when the credential is valid.
 * @throws {MdocValidationError} If the credential is invalid.
 */
export async function validateMdoc(credential: string): Promise<void> {
  const cborBytes = base64UrlToUint8Array(credential);
  const issuerSigned = parseSchema(
    issuerSignedSchema,
    decodeCbor(cborBytes, "IssuerSigned"),
    "IssuerSigned",
  );

  validateNamespaces(issuerSigned.nameSpaces);

  await validateIssuerAuth(issuerSigned.issuerAuth, issuerSigned.nameSpaces);
}

function base64UrlToUint8Array(data: string): Uint8Array {
  try {
    return new Uint8Array(base64url.decode(data));
  } catch (error) {
    throw new MdocValidationError(
      `Failed to decode base64url encoded credential - ${errorMessage(error)}`,
      "INVALID_BASE64URL",
    );
  }
}
