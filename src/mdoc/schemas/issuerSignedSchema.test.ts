import { issuerSignedSchema } from "./issuerSignedSchema";

describe("issuerSignedSchema", () => {
  const validItem = {
    digestID: 1,
    elementIdentifier: "test_element",
    elementValue: "test_value",
    random: new Uint8Array(16),
  };

  const validData = {
    nameSpaces: {
      "org.test.namespace.1": [validItem],
      "org.test.namespace.2": [validItem],
    },
    issuerAuth: [
      new Uint8Array(),
      new Map(),
      new Uint8Array(),
      new Uint8Array(),
    ] as const,
  };

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

    describe("IssuerSignedItem", () => {
      it("should return false when digestID is missing", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
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
            path: ["nameSpaces", "org.test.namespace.1", 0, "digestID"],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when digestID is not an integer", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1.5,
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
            path: ["nameSpaces", "org.test.namespace.1", 0, "digestID"],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when digestID is negative", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: -1,
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
            path: ["nameSpaces", "org.test.namespace.1", 0, "digestID"],
            code: "too_small",
          }),
        );
      });

      it("should return false when digestID is >= 2^31", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 2 ** 31,
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
            path: ["nameSpaces", "org.test.namespace.1", 0, "digestID"],
            code: "too_big",
          }),
        );
      });

      it("should return false when elementIdentifier is missing", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
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
            path: [
              "nameSpaces",
              "org.test.namespace.1",
              0,
              "elementIdentifier",
            ],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when random is missing", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
                elementIdentifier: "test_element",
                elementValue: "test_value",
              },
            ],
          },
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["nameSpaces", "org.test.namespace.1", 0, "random"],
            code: "custom",
          }),
        );
      });

      it("should return false when random is not a Uint8Array", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
                elementIdentifier: "test_element",
                elementValue: "test_value",
                random: "not-bytes",
              },
            ],
          },
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["nameSpaces", "org.test.namespace.1", 0, "random"],
            code: "custom",
          }),
        );
      });

      it("should return false when random is fewer than 16 bytes", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
                elementIdentifier: "test_element",
                elementValue: "test_value",
                random: new Uint8Array(15),
              },
            ],
          },
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["nameSpaces", "org.test.namespace.1", 0, "random"],
            message: "random must be at least 16 bytes",
          }),
        );
      });

      it("should return false when it contains additional properties", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                ...validItem,
                extra: "not allowed",
              },
            ],
          },
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["nameSpaces", "org.test.namespace.1", 0],
            code: "unrecognized_keys",
          }),
        );
      });

      it("should return false when digestID is not a number", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: "not-a-number",
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
            path: ["nameSpaces", "org.test.namespace.1", 0, "digestID"],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when elementIdentifier is not a string", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
                elementIdentifier: 123,
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
            path: [
              "nameSpaces",
              "org.test.namespace.1",
              0,
              "elementIdentifier",
            ],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when elementValue is missing", () => {
        const data = {
          ...validData,
          nameSpaces: {
            "org.test.namespace.1": [
              {
                digestID: 1,
                elementIdentifier: "test_element",
                random: new Uint8Array(16),
              },
            ],
          },
        };

        const result = issuerSignedSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["nameSpaces", "org.test.namespace.1", 0, "elementValue"],
            message: "elementValue is required",
          }),
        );
      });
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
            message: "must be instance of Uint8Array",
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
            message: "must be instance of Uint8Array",
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
            message: "must be instance of Uint8Array",
          }),
        );
      });
    });
  });

  it("should return true when data is valid", () => {
    const result = issuerSignedSchema.safeParse(validData);

    expect(result.success).toBe(true);
  });
});
