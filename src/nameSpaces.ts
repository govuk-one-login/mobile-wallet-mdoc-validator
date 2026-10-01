import { MdocValidationError } from "./MdocValidationError";
import { parseSchema } from "./parseSchema";
import { decodeCbor } from "./decodeCbor";
import { NameSpaces } from "./schemas/issuerSignedSchema";
import {
  IssuerSignedItem,
  issuerSignedItemSchema,
} from "./schemas/issuerSignedItemSchema";

function parseNamespaces(
  namespaces: NameSpaces,
): Record<string, IssuerSignedItem[]> {
  const parsed: Record<string, IssuerSignedItem[]> = {};
  for (const [namespace, items] of Object.entries(namespaces)) {
    parsed[namespace] = items.map((taggedItem) =>
      parseSchema(
        issuerSignedItemSchema,
        decodeCbor(taggedItem.contents, "IssuerSignedItem"),
        "IssuerSignedItem",
      ),
    );
  }
  return parsed;
}

export function validateNamespaces(namespaces: NameSpaces): void {
  for (const [namespace, items] of Object.entries(
    parseNamespaces(namespaces),
  )) {
    const digestIds = new Set<number>();
    const elementIdentifiers = new Set<string>();

    for (const item of items) {
      if (digestIds.has(item.digestID)) {
        throw new MdocValidationError(
          `Duplicate digest ID ${item.digestID.toString()} in namespace ${namespace}`,
          "INVALID_DIGEST_IDS",
        );
      }
      digestIds.add(item.digestID);

      if (elementIdentifiers.has(item.elementIdentifier)) {
        throw new MdocValidationError(
          `Duplicate element identifier ${item.elementIdentifier} in namespace ${namespace}`,
          "INVALID_ELEMENT_IDENTIFIERS",
        );
      }
      elementIdentifiers.add(item.elementIdentifier);
    }
  }
}
