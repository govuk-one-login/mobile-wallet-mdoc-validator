import { Tag } from "cbor2";
import { NameSpace } from "./namespaces";

export type IssuerAuth = [
  protectedHeader: Uint8Array,
  unprotectedHeader: Map<number, Uint8Array>,
  payload: Uint8Array,
  signature: Uint8Array,
];

export interface IssuerSignedItem {
  digestID: number;
  elementIdentifier: string;
  // TODO: Support all CBOR data element value types (e.g. number, null, Map, array) per ISO 18013-5 §8.3.2.1.2
  elementValue: string | boolean | Uint8Array | Tag;
  random: Uint8Array;
}

export interface TaggedIssuerSignedItem extends Omit<
  IssuerSignedItem,
  "elementValue"
> {
  // TODO: Support all CBOR data element value types (e.g. number, null, Map, array) per ISO 18013-5 §8.3.2.1.2
  elementValue: string | boolean | Uint8Array | Tag;
}

export interface IssuerSigned {
  issuerAuth: IssuerAuth;
  nameSpaces: Record<NameSpace, IssuerSignedItem[]>;
}

export interface TaggedIssuerSigned extends Omit<IssuerSigned, "nameSpaces"> {
  nameSpaces: Record<NameSpace, Tag[]>;
}
