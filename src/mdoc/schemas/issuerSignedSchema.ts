export const issuerSignedSchema = {
  $id: "issuer-signed",
  type: "object",
  required: ["nameSpaces", "issuerAuth"],
  properties: {
    nameSpaces: {
      type: "object",
    },
    issuerAuth: {
      type: "array",
      items: [
        {
          type: "object",
          instanceofUint8Array: true,
          description: "Protected header",
        },
        {
          type: "object",
          instanceofMap: true,
          description: "Unprotected header",
        },
        {
          type: "object",
          instanceofUint8Array: true,
          description: "Payload",
        },
        {
          type: "object",
          instanceofUint8Array: true,
          description: "Signature",
        },
      ],
      minItems: 4,
      maxItems: 4,
      additionalItems: false,
    },
  },
  additionalProperties: false,
};
