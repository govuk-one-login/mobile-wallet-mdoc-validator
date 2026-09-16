import { z } from "zod";

const dateTimeString = z.string().datetime();

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
        signed: dateTimeString,
        validFrom: dateTimeString,
        validUntil: dateTimeString,
        expectedUpdate: dateTimeString.optional(),
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
