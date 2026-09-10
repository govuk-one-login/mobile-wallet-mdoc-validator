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
  // TODO: We need to allow more element value types
  elementValue: string | boolean | Uint8Array;
  random: Uint8Array;
}

export interface TaggedIssuerSignedItem extends Omit<
  IssuerSignedItem,
  "elementValue"
> {
  // TODO: We need to allow more element value types
  elementValue: string | boolean | Uint8Array | Tag;
}

export interface IssuerSigned {
  issuerAuth: IssuerAuth;
  nameSpaces: Record<NameSpace, IssuerSignedItem[]>;
}

export interface TaggedIssuerSigned extends Omit<IssuerSigned, "nameSpaces"> {
  nameSpaces: Record<NameSpace, Tag[]>;
}
