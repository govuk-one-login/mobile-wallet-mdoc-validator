import { decode, Tag } from "cbor2";
import { base64url } from "jose";
import "cbor2/types";
import { ZodError } from "zod";
import { validateIssuerAuth } from "./validateIssuerAuth";
import { TAGS } from "./constants/tags";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { taggedIssuerSignedSchema } from "./schemas/issuerSignedSchema";
import { validateDigestIds } from "./validateDigestIds";

/**
 * Validates a base64url-encoded mdoc credential string.
 *
 * @param credential - Base64url-encoded credential.
 * @returns true if the credential is valid; otherwise, throws an error.
 */
export async function validateMdoc(credential: string): Promise<boolean> {
  const cborBytes = base64UrlToUint8Array(credential);

  const taggedIssuerSigned = validateTaggedIssuerSignedSchema(
    decodeCbor(cborBytes),
  );

  validateDigestIds(taggedIssuerSigned.nameSpaces);

  await validateIssuerAuth(
    taggedIssuerSigned.issuerAuth,
    taggedIssuerSigned.nameSpaces,
  );

  return true;
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

/*
 * Override the default CBOR tag 0 (RFC3339 date/time string) decoder.
 * By default, data with tag 0 is automatically parsed into a JavaScript Date.
 * Registering this custom decoder instead wraps any tag 0 value in a Tag object,
 * preserving both the tag number (0) and its contents as-is.
 *
 * This allows for explicit verification that a given value was actually tagged with 0,
 * instead of being silently converted to a Date type.
 */
Tag.registerDecoder(
  TAGS.DATE_TIME,
  (tag) => new Tag(TAGS.DATE_TIME, tag.contents),
);

function decodeCbor(credential: Uint8Array): unknown {
  try {
    return decode(credential);
  } catch (error) {
    throw new MdocValidationError(
      `Failed to decode CBOR encoded credential - ${errorMessage(error)}`,
      "INVALID_CBOR",
    );
  }
}

function validateTaggedIssuerSignedSchema(data: unknown) {
  try {
    return taggedIssuerSignedSchema.parse(data);
  } catch (error) {
    if (error instanceof ZodError) {
      const errorDetails = error.issues
        .map((issue) => `${issue.path.join("/") || "root"}: ${issue.message}`)
        .join("; ");

      throw new MdocValidationError(
        `TaggedIssuerSigned does not comply with schema - ${errorDetails}`,
        "INVALID_SCHEMA",
      );
    }
    throw error;
  }
}
