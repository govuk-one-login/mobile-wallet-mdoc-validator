import { mobileSecurityObjectSchema } from "./mobileSecurityObjectSchema";
import { MobileSecurityObject } from "../types/mobileSecurityObject";

describe("mobileSecurityObjectSchema", () => {
  const validData: MobileSecurityObject = {
    version: "1.0",
    digestAlgorithm: "SHA-256",
    deviceKeyInfo: {
      deviceKey: new Map(),
      keyAuthorizations: {
        nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
      },
    },
    valueDigests: {
      "org.test.namespace.1": new Map(),
      "org.test.namespace.2": new Map(),
    },
    docType: "org.test.document",
    validityInfo: {
      signed: "2023-10-10T10:10:10Z",
      validFrom: "2023-10-10T10:10:10Z",
      validUntil: "2024-10-10T10:10:10Z",
      expectedUpdate: "2024-06-01T00:00:00Z",
    },
    status: {
      status_list: {
        idx: 1,
        uri: "https://example.com/status",
      },
    },
  };

  it("should return false when it contains additional properties", () => {
    const data = { ...validData, extra: "not allowed" };

    const result = mobileSecurityObjectSchema.safeParse(data);

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        code: "unrecognized_keys",
        message: "Unrecognized key(s) in object: 'extra'",
      }),
    );
  });

  it.each([
    {
      field: "version",
      data: {
        digestAlgorithm: "SHA-256" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        docType: "org.test.document",
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "digestAlgorithm",
      data: {
        version: "1.0" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        docType: "org.test.document",
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "deviceKeyInfo",
      data: {
        version: "1.0" as const,
        digestAlgorithm: "SHA-256" as const,
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        docType: "org.test.document",
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "valueDigests",
      data: {
        version: "1.0" as const,
        digestAlgorithm: "SHA-256" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        docType: "org.test.document",
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "docType",
      data: {
        version: "1.0" as const,
        digestAlgorithm: "SHA-256" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "validityInfo",
      data: {
        version: "1.0" as const,
        digestAlgorithm: "SHA-256" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        docType: "org.test.document",
        status: {
          status_list: { idx: 1, uri: "https://example.com/status" },
        },
      },
    },
    {
      field: "status",
      data: {
        version: "1.0" as const,
        digestAlgorithm: "SHA-256" as const,
        deviceKeyInfo: {
          deviceKey: new Map(),
          keyAuthorizations: {
            nameSpaces: ["org.test.namespace.1", "org.test.namespace.2"],
          },
        },
        valueDigests: {
          "org.test.namespace.1": new Map(),
          "org.test.namespace.2": new Map(),
        },
        docType: "org.test.document",
        validityInfo: {
          signed: "2023-10-10T10:10:10Z",
          validFrom: "2023-10-10T10:10:10Z",
          validUntil: "2024-10-10T10:10:10Z",
          expectedUpdate: "2024-06-01T00:00:00Z",
        },
      },
    },
  ])("should return false when $field is missing", ({ data }) => {
    const result = mobileSecurityObjectSchema.safeParse(data);

    expect(result.success).toBe(false);
  });

  describe("version", () => {
    it("should return false when it is not '1.0'", () => {
      const data = { ...validData, version: "2.0" };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["version"],
          code: "invalid_literal",
        }),
      );
    });
  });

  describe("digestAlgorithm", () => {
    it("should return false when it is not 'SHA-256'", () => {
      const data = { ...validData, digestAlgorithm: "SHA-512" };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["digestAlgorithm"],
          code: "invalid_literal",
        }),
      );
    });
  });

  describe("deviceKeyInfo", () => {
    it("should return false when deviceKey is missing", () => {
      const data = {
        ...validData,
        deviceKeyInfo: {
          keyAuthorizations: validData.deviceKeyInfo.keyAuthorizations,
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["deviceKeyInfo", "deviceKey"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when keyAuthorizations is missing", () => {
      const data = {
        ...validData,
        deviceKeyInfo: {
          deviceKey: new Map(),
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["deviceKeyInfo", "keyAuthorizations"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it contains additional properties", () => {
      const data = {
        ...validData,
        deviceKeyInfo: {
          ...validData.deviceKeyInfo,
          extra: "not allowed",
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          code: "unrecognized_keys",
          path: ["deviceKeyInfo"],
        }),
      );
    });

    describe("deviceKey", () => {
      it("should return false when it is not a Map", () => {
        const data = {
          ...validData,
          deviceKeyInfo: {
            deviceKey: {},
            keyAuthorizations: validData.deviceKeyInfo.keyAuthorizations,
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
      });
    });

    describe("keyAuthorizations", () => {
      it("should return false when nameSpaces is missing", () => {
        const data = {
          ...validData,
          deviceKeyInfo: {
            deviceKey: new Map(),
            keyAuthorizations: {},
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["deviceKeyInfo", "keyAuthorizations", "nameSpaces"],
            code: "invalid_type",
          }),
        );
      });

      describe("nameSpaces", () => {
        it("should return false when items are not unique", () => {
          const data = {
            ...validData,
            deviceKeyInfo: {
              deviceKey: new Map(),
              keyAuthorizations: {
                nameSpaces: ["org.test.namespace.1", "org.test.namespace.1"],
              },
            },
          };

          const result = mobileSecurityObjectSchema.safeParse(data);

          expect(result.success).toBe(false);
          expect(result.error?.issues).toContainEqual(
            expect.objectContaining({
              path: ["deviceKeyInfo", "keyAuthorizations", "nameSpaces"],
              message: "must NOT have duplicate items",
            }),
          );
        });
      });
    });
  });

  describe("valueDigests", () => {
    describe("org.test.namespace.1", () => {
      it("should return false when it is not a Map", () => {
        const data = {
          ...validData,
          valueDigests: {
            "org.test.namespace.1": {},
            "org.test.namespace.2": new Map(),
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
      });
    });

    describe("org.test.namespace.2", () => {
      it("should return false when it is not a Map", () => {
        const data = {
          ...validData,
          valueDigests: {
            "org.test.namespace.1": new Map(),
            "org.test.namespace.2": {},
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
      });
    });
  });

  describe("validityInfo", () => {
    it("should return false when signed is missing", () => {
      const data = {
        ...validData,
        validityInfo: {
          validFrom: validData.validityInfo.validFrom,
          validUntil: validData.validityInfo.validUntil,
          expectedUpdate: validData.validityInfo.expectedUpdate,
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["validityInfo", "signed"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when validFrom is missing", () => {
      const data = {
        ...validData,
        validityInfo: {
          signed: validData.validityInfo.signed,
          validUntil: validData.validityInfo.validUntil,
          expectedUpdate: validData.validityInfo.expectedUpdate,
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["validityInfo", "validFrom"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when validUntil is missing", () => {
      const data = {
        ...validData,
        validityInfo: {
          signed: validData.validityInfo.signed,
          validFrom: validData.validityInfo.validFrom,
          expectedUpdate: validData.validityInfo.expectedUpdate,
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["validityInfo", "validUntil"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it contains additional properties", () => {
      const data = {
        ...validData,
        validityInfo: {
          ...validData.validityInfo,
          extra: "not allowed",
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          code: "unrecognized_keys",
          path: ["validityInfo"],
        }),
      );
    });

    describe("signed", () => {
      it("should return false when it is not a valid date-time", () => {
        const data = {
          ...validData,
          validityInfo: {
            ...validData.validityInfo,
            signed: "not-a-date",
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["validityInfo", "signed"],
            code: "invalid_string",
          }),
        );
      });
    });

    describe("validFrom", () => {
      it("should return false when it is not a valid date-time", () => {
        const data = {
          ...validData,
          validityInfo: {
            ...validData.validityInfo,
            validFrom: "not-a-date",
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["validityInfo", "validFrom"],
            code: "invalid_string",
          }),
        );
      });
    });

    describe("validUntil", () => {
      it("should return false when it is not a valid date-time", () => {
        const data = {
          ...validData,
          validityInfo: {
            ...validData.validityInfo,
            validUntil: "not-a-date",
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["validityInfo", "validUntil"],
            code: "invalid_string",
          }),
        );
      });
    });

    describe("expectedUpdate", () => {
      it("should return false when it is not a valid date-time", () => {
        const data = {
          ...validData,
          validityInfo: {
            ...validData.validityInfo,
            expectedUpdate: "not-a-date",
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["validityInfo", "expectedUpdate"],
            code: "invalid_string",
          }),
        );
      });

      it("should return true when it is absent", () => {
        const data = {
          ...validData,
          validityInfo: {
            signed: validData.validityInfo.signed,
            validFrom: validData.validityInfo.validFrom,
            validUntil: validData.validityInfo.validUntil,
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(true);
      });
    });
  });

  describe("status", () => {
    it("should return false when status_list is missing", () => {
      const data = { ...validData, status: {} };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          path: ["status", "status_list"],
          code: "invalid_type",
        }),
      );
    });

    it("should return false when it contains additional properties", () => {
      const data = {
        ...validData,
        status: {
          status_list: {
            idx: 1,
            uri: "https://example.com/status",
          },
          extra: "not allowed",
        },
      };

      const result = mobileSecurityObjectSchema.safeParse(data);

      expect(result.success).toBe(false);
      expect(result.error?.issues).toContainEqual(
        expect.objectContaining({
          code: "unrecognized_keys",
          path: ["status"],
        }),
      );
    });

    describe("status_list", () => {
      it("should return false when idx is missing", () => {
        const data = {
          ...validData,
          status: {
            status_list: {
              uri: "https://example.com/status",
            },
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["status", "status_list", "idx"],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when uri is missing", () => {
        const data = {
          ...validData,
          status: {
            status_list: {
              idx: 1,
            },
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            path: ["status", "status_list", "uri"],
            code: "invalid_type",
          }),
        );
      });

      it("should return false when it contains additional properties", () => {
        const data = {
          ...validData,
          status: {
            status_list: {
              idx: 1,
              uri: "https://example.com/status",
              extra: "not allowed",
            },
          },
        };

        const result = mobileSecurityObjectSchema.safeParse(data);

        expect(result.success).toBe(false);
        expect(result.error?.issues).toContainEqual(
          expect.objectContaining({
            code: "unrecognized_keys",
            path: ["status", "status_list"],
          }),
        );
      });

      describe("idx", () => {
        it("should return false when it is not a number", () => {
          const data = {
            ...validData,
            status: {
              status_list: {
                idx: "not-a-number",
                uri: "https://example.com/status",
              },
            },
          };

          const result = mobileSecurityObjectSchema.safeParse(data);

          expect(result.success).toBe(false);
          expect(result.error?.issues).toContainEqual(
            expect.objectContaining({
              path: ["status", "status_list", "idx"],
              code: "invalid_type",
            }),
          );
        });
      });

      describe("uri", () => {
        it("should return false when it is not a valid URI", () => {
          const data = {
            ...validData,
            status: {
              status_list: {
                idx: 1,
                uri: "not-a-uri",
              },
            },
          };

          const result = mobileSecurityObjectSchema.safeParse(data);

          expect(result.success).toBe(false);
          expect(result.error?.issues).toContainEqual(
            expect.objectContaining({
              path: ["status", "status_list", "uri"],
              code: "invalid_string",
            }),
          );
        });
      });
    });
  });

  it("should return true when data is valid", () => {
    const result = mobileSecurityObjectSchema.safeParse(validData);

    expect(result.success).toBe(true);
  });
});
