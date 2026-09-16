import { Tag } from "cbor2";
import { IssuerSignedItem } from "../schemas/issuerSignedSchema";

export interface TaggedIssuerSignedItem extends Omit<
  IssuerSignedItem,
  "elementValue"
> {
  // TODO: Support all CBOR data element value types (e.g. number, null, Map, array) per ISO 18013-5 §8.3.2.1.2
  elementValue: string | boolean | Uint8Array | Tag;
}
