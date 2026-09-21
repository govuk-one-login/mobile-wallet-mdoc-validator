import { z } from "zod";

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
    // The spec allows any value (DataElementValue = any), so null is accepted.
    // CBOR undefined decodes to JS undefined and is rejected as missing.
    elementValue: z.custom<unknown>((val) => val !== undefined, {
      message: "elementValue is required",
    }),
    // Spec requires at least 16 bytes of randomness per item.
    random: z.instanceof(Uint8Array).refine((r) => r.length >= 16, {
      message: "random must be at least 16 bytes",
    }),
  })
  .strict();