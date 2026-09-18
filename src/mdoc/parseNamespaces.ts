import {IssuerSignedItem, issuerSignedItemSchema, NameSpaces} from "./schemas/issuerSignedSchema";
import {decode, Tag} from "cbor2";
import {MdocValidationError} from "./MdocValidationError";
import {parseSchema} from "./parseSchema";

export type ParsedItem = {
  tag: Tag;
  item: IssuerSignedItem;
};

export type ParsedNamespaces = Record<string, ParsedItem[]>;

function parseIssuerSignedItem(taggedItem: Tag, namespace: string): ParsedItem {
  const { contents } = taggedItem;
  if (!(contents instanceof Uint8Array)) {
    throw new MdocValidationError(
      `IssuerSignedItem contents is not a Uint8Array in namespace ${namespace}`,
      "INVALID_SCHEMA",
    );
  }
  return {
    tag: taggedItem,
    item: parseSchema(issuerSignedItemSchema, decode(contents), "IssuerSignedItem"),
  };
}

export function parseNamespaces(namespaces: NameSpaces): ParsedNamespaces {
  const parsed: ParsedNamespaces = {};
  for (const [namespace, items] of Object.entries(namespaces)) {
    parsed[namespace] = items.map((taggedItem) =>
      parseIssuerSignedItem(taggedItem, namespace),
    );
  }
  return parsed;
}