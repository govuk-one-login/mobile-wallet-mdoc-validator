import { Tag } from "cbor2";
import { MobileSecurityObject } from "../schemas/mobileSecurityObjectSchema";

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
