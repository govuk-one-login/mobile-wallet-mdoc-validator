import { Tag } from "cbor2";
import { z } from "zod";
import { TAGS } from "../constants/tags";

const dateTimeTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.DATE_TIME, {
    message: "must be tagged with 0 (date-time)",
  })
  .refine((tag) => typeof tag.contents === "string", {
    message: "tag contents must be a string",
  });

const cborEncodedDataTag = z
  .instanceof(Tag)
  .refine((tag) => tag.tag === TAGS.ENCODED_CBOR_DATA, {
    message: "must be tagged with 24 (encoded CBOR data)",
  })
  .refine(
    (tag): tag is Tag & { contents: Uint8Array } =>
      tag.contents instanceof Uint8Array,
    { message: "tag contents must be a Uint8Array" },
  );

export const mobileSecurityObjectBytesSchema = cborEncodedDataTag;

export const mobileSecurityObjectSchema = z
  .object({
    version: z.literal("1.0"),
    digestAlgorithm: z.literal("SHA-256"),
    deviceKeyInfo: z
      .object({
        deviceKey: z.map(z.unknown(), z.unknown()),
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
    valueDigests: z
      .record(z.map(z.number(), z.instanceof(Uint8Array)))
      .refine((obj) => Object.keys(obj).length > 0, {
        message: "must NOT have fewer than 1 properties",
      }),
    docType: z.string(),
    validityInfo: z
      .object({
        signed: dateTimeTag,
        validFrom: dateTimeTag,
        validUntil: dateTimeTag,
        expectedUpdate: dateTimeTag.optional(),
      })
      .strict(),
    status: z
      .object({
        status_list: z
          .object({
            idx: z.number(),
            uri: z.string().url(),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

export type MobileSecurityObject = z.infer<typeof mobileSecurityObjectSchema>;
export type ValidityInfo = MobileSecurityObject["validityInfo"];
export type ValueDigests = MobileSecurityObject["valueDigests"];
