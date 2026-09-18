import { decode, Tag } from "cbor2";
import { base64url } from "jose";
import "cbor2/types";
import { validateIssuerAuth } from "./validateIssuerAuth";
import { TAGS } from "./constants/tags";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { issuerSignedSchema } from "./schemas/issuerSignedSchema";
import { parseSchema } from "./parseSchema";
import {
  validateNamespaces,
} from "./issuerSignedItems";
import { decodeCbor } from "./decodeCbor";

/**
 * Validates a base64url-encoded mdoc credential string.
 *
 * @param credential - Base64url-encoded credential.
 * @returns true if the credential is valid; otherwise, throws an error.
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
