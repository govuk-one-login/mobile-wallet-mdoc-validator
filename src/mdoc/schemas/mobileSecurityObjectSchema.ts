export const mobileSecurityObjectSchema = {
  $id: "mobile-security-object",
  type: "object",
  required: [
    "version",
    "digestAlgorithm",
    "deviceKeyInfo",
    "valueDigests",
    "docType",
    "validityInfo",
    "status",
  ],
  additionalProperties: false,
  properties: {
    version: {
      type: "string",
      enum: ["1.0"],
    },
    digestAlgorithm: {
      type: "string",
      enum: ["SHA-256"],
    },
    deviceKeyInfo: {
      type: "object",
      required: ["deviceKey", "keyAuthorizations"],
      additionalProperties: false,
      properties: {
        deviceKey: {
          type: "object",
          instanceofMap: true,
        },
        keyAuthorizations: {
          type: "object",
          required: ["nameSpaces"],
          additionalProperties: false,
          properties: {
            nameSpaces: {
              type: "array",
              minItems: 1,
              uniqueItems: true,
              items: {
                type: "string",
              },
            },
          },
        },
      },
    },
    // TODO: how to make this document agnostic?
    valueDigests: {
      type: "object",
      minProperties: 1,
      additionalProperties: {
        type: "object",
        instanceofMap: true,
      },
    },
    docType: {
      type: "string",
    },
    validityInfo: {
      type: "object",
      required: ["signed", "validFrom", "validUntil"],
      properties: {
        signed: { type: "string", format: "date-time" },
        validFrom: { type: "string", format: "date-time" },
        validUntil: { type: "string", format: "date-time" },
        expectedUpdate: { type: "string", format: "date-time" },
      },
      additionalProperties: false,
    },
    status: {
      type: "object",
      required: ["status_list"],
      properties: {
        status_list: {
          type: "object",
          required: ["idx", "uri"],
          properties: {
            idx: { type: "number" },
            uri: { type: "string", format: "uri" },
          },
          additionalProperties: false,
        },
      },
      additionalProperties: false,
    },
  },
};
