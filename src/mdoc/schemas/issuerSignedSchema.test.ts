import { encode, Tag } from "cbor2";
import {
  issuerSignedItemSchema,
  issuerSignedSchema,
} from "./issuerSignedSchema";

describe("issuerSignedSchema", () => {
  const validTaggedItem = new Tag(
    24,
    encode({
      digestID: 1,
      elementIdentifier: "test_element",
      elementValue: "test_value",
      random: new Uint8Array(16),
    }),
  );

  const validData = {
    nameSpaces: {
      "org.test.namespace.1": [validTaggedItem],
      "org.test.namespace.2": [validTaggedItem],
    },
    issuerAuth: [
      new Uint8Array(),
      new Map(),
      new Uint8Array(),
      new Uint8Array(),
    ] as const,
  };

  it("should return true when data is valid", () => {
    const result = issuerSignedSchema.safeParse(validData);

    expect(result.success).toBe(true);
  });

  it("should return false when it contains additional properties", () => {
    const data = {
      ...validData,
      extra: "not allowed",
    };

    const result = issuerSignedSchema.safeParse(data);

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        code: "unrecognized_keys",
        message: "Unrecognized key(s) in object: 'extra'",
      }),
    );
  });

  it("should return false when nameSpaces is missing", () => {
    const data = {
      issuerAuth: validData.issuerAuth,
    };

    const result = issuerSignedSchema.safeParse(data);

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        path: ["nameSpaces"],
        code: "invalid_type",
      }),
    );
  });

  it("should return false when issuerAuth is missing", () => {
    const data = {
      nameSpaces: validData.nameSpaces,
    };

    const result = issuerSignedSchema.safeParse(data);

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        path: ["issuerAuth"],
        code: "invalid_type",
      }),
    );
  });

  describe("nameSpaces", () => {
    it("should return false when it is empty", () => {
      const data = { ...validData, nameSpaces: {} };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["nameSpaces"],
          message: "must NOT have fewer than 1 properties",
        }),
      );
    });

    it("should return false when a namespace has no items", () => {
      const data = {
        ...validData,
        nameSpaces: {
          "org.test.namespace.1": [],
        },
      };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["nameSpaces", "org.test.namespace.1"],
          code: "too_small",
          message: "must NOT have fewer than 1 items",
        }),
      );
    });

    it("should return false when an item is not a Tag", () => {
      const data = {
        ...validData,
        nameSpaces: {
          "org.test.namespace.1": [
            {
              digestID: 1,
              elementIdentifier: "test_element",
              elementValue: "test_value",
              random: new Uint8Array(16),
            },
          ],
        },
      };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["nameSpaces", "org.test.namespace.1", 0],
          code: "custom",
        }),
      );
    });

    it("should return false when an item is a Tag with wrong tag number", () => {
      const data = {
        ...validData,
        nameSpaces: {
          "org.test.namespace.1": [
            new Tag(
              99,
              encode({
                digestID: 1,
                elementIdentifier: "test_element",
                elementValue: "test_value",
                random: new Uint8Array(16),
              }),
            ),
          ],
        },
      };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["nameSpaces", "org.test.namespace.1", 0],
          message: "must be tagged with 24 (encoded CBOR data)",
        }),
      );
    });
  });

  describe("issuerAuth", () => {
    it("should return false when it has fewer than 4 items", () => {
      const data = {
        ...validData,
        issuerAuth: [new Uint8Array(), new Map(), new Uint8Array()],
      };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["issuerAuth"],
          code: "too_small",
        }),
      );
    });

    it("should return false when it has more than 4 items", () => {
      const data = {
        ...validData,
        issuerAuth: [
          new Uint8Array(),
          new Map(),
          new Uint8Array(),
          new Uint8Array(),
          new Uint8Array(),
        ],
      };

      const result = issuerSignedSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["issuerAuth"],
          code: "too_big",
        }),
      );
    });

    describe("Protected header", () => {
      it("should return false when it is not a Uint8Array", () => {
        const data = {
          ...validData,
          issuerAuth: [
            new Map(), // protected header
            new Map(),
            new Uint8Array(),
            new Uint8Array(),
          ] as const,
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["issuerAuth", 0],
            code: "custom",
            message: "Input not instance of Uint8Array",
          }),
        );
      });
    });

    describe("Unprotected header", () => {
      it("should return false when it is not a Map", () => {
        const data = {
          ...validData,
          issuerAuth: [
            new Uint8Array(),
            new Uint8Array(), // unprotected header
            new Uint8Array(),
            new Uint8Array(),
          ] as const,
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
      });
    });

    describe("Payload", () => {
      it("should return false when it is not a Uint8Array", () => {
        const data = {
          ...validData,
          issuerAuth: [
            new Uint8Array(),
            new Map(),
            new Map(), // payload
            new Uint8Array(),
          ] as const,
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["issuerAuth", 2],
            code: "custom",
            message: "Input not instance of Uint8Array",
          }),
        );
      });
    });

    describe("signature", () => {
      it("should return false when it is not a Uint8Array", () => {
        const data = {
          ...validData,
          issuerAuth: [
            new Uint8Array(),
            new Map(),
            new Uint8Array(),
            new Map(), // signature
          ] as const,
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["issuerAuth", 3],
            code: "custom",
            message: "Input not instance of Uint8Array",
          }),
        );
      });
    });
  });
});

describe("issuerSignedItemSchema", () => {
  const validItem = {
    digestID: 1,
    elementIdentifier: "test_element",
    elementValue: "test_value",
    random: new Uint8Array(16),
  };

  it("should return true when data is valid", () => {
    const result = issuerSignedItemSchema.safeParse(validItem);

    expect(result.success).toBe(true);
  });

  it("should return false when it contains additional properties", () => {
    const data = {
      ...validItem,
      extra: "not allowed",
    };

    const result = issuerSignedItemSchema.safeParse(data);

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        code: "unrecognized_keys",
      }),
    );
  });

  describe("digestID", () => {
    it("should return false when it is missing", () => {
      const data = {
        elementIdentifier: "test_element",
        elementValue: "test_value",
        random: new Uint8Array(16),
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestID"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it is not a number", () => {
      const data = {
        ...validItem,
        digestID: "not-a-number",
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestID"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it is not an integer", () => {
      const data = {
        ...validItem,
        digestID: 1.5,
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestID"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it is negative", () => {
      const data = {
        ...validItem,
        digestID: -1,
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestID"],
          code: "too_small",
        }),
      );
    });

    it("should return false when it is >= 2^31", () => {
      const data = {
        ...validItem,
        digestID: 2 ** 31,
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestID"],
          code: "too_big",
        }),
      );
    });
  });

  describe("elementIdentifier", () => {
    it("should return false when it is missing", () => {
      const data = {
        digestID: 1,
        elementValue: "test_value",
        random: new Uint8Array(16),
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["elementIdentifier"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it is not a string", () => {
      const data = {
        ...validItem,
        elementIdentifier: 123,
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["elementIdentifier"],
          code: "invalid_type",
        }),
      );
    });
  });

  describe("elementValue", () => {
    it("should return false when it is missing", () => {
      const data = {
        digestID: 1,
        elementIdentifier: "test_element",
        random: new Uint8Array(16),
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["elementValue"],
          message: "elementValue is required",
        }),
      );
    });
  });

  describe("random", () => {
    it("should return false when it is missing", () => {
      const data = {
        digestID: 1,
        elementIdentifier: "test_element",
        elementValue: "test_value",
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["random"],
          code: "custom",
        }),
      );
    });

    it("should return false when it is not a Uint8Array", () => {
      const data = {
        ...validItem,
        random: "not-bytes",
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["random"],
          code: "custom",
        }),
      );
    });

    it("should return false when it is fewer than 16 bytes", () => {
      const data = {
        ...validItem,
        random: new Uint8Array(15),
      };

      const result = issuerSignedItemSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["random"],
          message: "random must be at least 16 bytes",
        }),
      );
    });
  });
});
