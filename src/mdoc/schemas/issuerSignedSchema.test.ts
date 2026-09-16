import { issuerSignedSchema } from "./issuerSignedSchema";

describe("issuerSignedSchema", () => {
  const validData = {
    nameSpaces: {
      "org.test.namespace.1": [new Uint8Array()],
      "org.test.namespace.2": [new Uint8Array()],
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
