import { z } from "zod";
import { elementValueSchema } from "./elementValueSchema";

export const issuerSignedItemSchema = z
  .object({
    // Spec requires digest IDs to be smaller than 2^31.
    digestID: z
      .number()
      .int()
      .nonnegative()
      .lt(2 ** 31),
    // No minimum length: CBOR allows empty text strings and the spec
    // defines DataElementIdentifier as tstr with no size constraint.
    elementIdentifier: z.string(),
    // Although the spec defines DataElementValue as any, we enforce the
    // builder's bounded, typed rules so validator and builder stay aligned.
    // null and undefined are both rejected.
    elementValue: elementValueSchema,
    // Spec requires at least 16 bytes of randomness per item.
    random: z.instanceof(Uint8Array).refine((r) => r.length >= 16, {
      message: "random must be at least 16 bytes",
    }),
  })
  .strict();

export type IssuerSignedItem = z.infer<typeof issuerSignedItemSchema>;
