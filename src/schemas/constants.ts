/**
 * Bounds for DataElementValue validation. These mirror the mdoc builder's
 * documented validation rules so the validator and builder stay aligned.
 */
export const ELEMENT_VALUE_LIMITS = {
  string: {
    minLength: 1,
    maxLength: 150,
  },
  number: {
    min: Number.MIN_SAFE_INTEGER,
    max: Number.MAX_SAFE_INTEGER,
  },
  uint8Array: {
    minByteLength: 1,
    // 1.5 MB.
    maxByteLength: 1572864,
  },
  collections: {
    minLength: 1,
    maxLength: 256,
  },
} as const;
