import { Tag } from "cbor2";

export interface DeviceKeyInfo {
  deviceKey: Map<unknown, unknown>;
  keyAuthorizations: {
    nameSpaces: string[];
  };
}

export interface ValueDigests {
  [namespace: string]: Map<unknown, Uint8Array>;
}

export interface ValidityInfo {
  signed: string;
  validFrom: string;
  validUntil: string;
  expectedUpdate?: string;
}

export interface MobileSecurityObject {
  version: "1.0";
  digestAlgorithm: "SHA-256";
  deviceKeyInfo: DeviceKeyInfo;
  valueDigests: ValueDigests;
  docType: string;
  validityInfo: ValidityInfo;
  status: {
    status_list: {
      idx: number;
      uri: string;
    };
  };
}

export interface TaggedMobileSecurityObject extends Omit<
  MobileSecurityObject,
  "validityInfo"
> {
  validityInfo: {
    signed: Tag;
    validFrom: Tag;
    validUntil: Tag;
    expectedUpdate?: Tag;
  };
}
