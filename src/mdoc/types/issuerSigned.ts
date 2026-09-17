import { Tag } from "cbor2";

export type IssuerAuth = [
  protectedHeader: Uint8Array,
  unprotectedHeader: Map<number, Uint8Array>,
  payload: Uint8Array,
  signature: Uint8Array,
];

export interface IssuerSignedItem {
  digestID: number;
  elementIdentifier: string;
  elementValue: string | boolean | Uint8Array;
  random: Uint8Array;
}

export interface TaggedIssuerSignedItem extends Omit<
  IssuerSignedItem,
  "elementValue"
> {
  elementValue: string | boolean | Uint8Array | Tag;
}

export interface IssuerSigned {
  issuerAuth: IssuerAuth;
  nameSpaces: Record<string, IssuerSignedItem[]>;
}

export interface TaggedIssuerSigned extends Omit<IssuerSigned, "nameSpaces"> {
  nameSpaces: Record<string, Tag[]>;
}
