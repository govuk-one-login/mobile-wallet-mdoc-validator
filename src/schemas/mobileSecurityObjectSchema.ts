import { z } from "zod";
import { dateTimeTag } from "./cborTags";
import { latin1StringMax128, latin1StringMax256 } from "./helpers/latin1";

// Upper bound for status_list.idx: the maximum value of an unsigned 32-bit
// integer (2^32 - 1).
const UINT32_MAX = 4294967295;

export const mobileSecurityObjectSchema = z
  .object({
    version: z.literal("1.0"),
    // Only SHA-256 is supported. Widening this means the hash used in
    // validateDigestsMatchMso must be chosen from this field.
    digestAlgorithm: z.literal("SHA-256"),
    // .strict() rejects the spec's optional keyInfo field.
    deviceKeyInfo: z
      .object({
        // Loosely typed here; key type, curve and coordinates are checked
        // in validateDeviceKey.
        deviceKey: z.map(z.unknown(), z.unknown()),
        // Narrower than the spec: keyAuthorizations and its nameSpaces are
        // optional there but required here, and .strict() rejects the
        // dataElements alternative.
        keyAuthorizations: z
          .object({
            nameSpaces: z
              .array(z.string())
              .min(1)
              .refine((items) => new Set(items).size === items.length, {
                message: "must NOT have duplicate items",
              }),
          })
          .strict(),
      })
      .strict(),
    // Namespace to (digest ID to digest). Matched against presented items in
    // validateDigestsMatchMso.
    valueDigests: z
      .record(latin1StringMax256, z.map(z.number(), z.instanceof(Uint8Array)))
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    docType: latin1StringMax128,
    // Structure only. Date ordering and expiry are checked in validateValidityInfo.
    validityInfo: z
      .object({
        signed: dateTimeTag,
        validFrom: dateTimeTag,
        validUntil: dateTimeTag,
        expectedUpdate: dateTimeTag.optional(),
      })
      .strict(),
    // Required here, though not every mdoc carries status. Credentials
    // issued without it are rejected.
    status: z
      .object({
        status_list: z
          .object({
            idx: z.int().min(0).max(UINT32_MAX),
            uri: z.url().max(2048),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

export type MobileSecurityObject = z.infer<typeof mobileSecurityObjectSchema>;
export type ValidityInfo = MobileSecurityObject["validityInfo"];
export type ValueDigests = MobileSecurityObject["valueDigests"];
