import { decode } from "cbor2";
import { MdocValidationError } from "./MdocValidationError";
import {
  issuerSignedItemSchema,
  NameSpaces,
} from "./schemas/issuerSignedSchema";

export function validateDigestIds(namespaces: NameSpaces) {
  for (const [namespace, items] of Object.entries(namespaces)) {
    const digestIds = items.map((taggedItem) => {
      if (!(taggedItem.contents instanceof Uint8Array)) {
        throw new MdocValidationError(
          `IssuerSignedItem contents is not a Uint8Array in namespace ${namespace}`,
          "INVALID_SCHEMA",
        );
      }
      const item = issuerSignedItemSchema.parse(decode(taggedItem.contents));
      return item.digestID;
    });

    if (!checkUnique(digestIds)) {
      throw new MdocValidationError(
        `Digest IDs are not unique for namespace ${namespace}`,
        "INVALID_DIGEST_IDS",
      );
    }
  }
}

function checkUnique(digestIds: number[]): boolean {
  return new Set(digestIds).size === digestIds.length;
}
