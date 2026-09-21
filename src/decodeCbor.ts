import { decode, Tag } from "cbor2";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { TAGS } from "./constants/tags";

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

export function decodeCbor(bytes: Uint8Array, label: string): unknown {
  try {
    return decode(bytes, { rejectDuplicateKeys: true });
  } catch (error) {
    throw new MdocValidationError(
      `${label} is not valid CBOR - ${errorMessage(error)}`,
      "INVALID_CBOR",
    );
  }
}
