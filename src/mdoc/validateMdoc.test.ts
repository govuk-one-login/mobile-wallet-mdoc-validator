import { encode } from "cbor2";
import { base64url } from "jose";
import { TestMdocBuilder } from "./TestMdocBuilder";
import { validateMdoc } from "./validateMdoc";

describe("validateMdoc", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2025-09-10T15:30:00Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("accepts a valid credential", async () => {
    await expect(
      validateMdoc(new TestMdocBuilder().build()),
    ).resolves.toBeUndefined();
  });

  it.todo(
    "accepts a credential from an external issuer (i.e. not TestMdocBuilder)",
  );

  it("rejects invalid base64url", async () => {
    await expect(validateMdoc("invalid@base64url!")).rejects.toThrow(
      "Failed to decode base64url encoded credential - The input to be decoded is not correctly encoded.",
    );
  });

  it("rejects invalid CBOR", async () => {
    await expect(validateMdoc(base64url.encode("invalidCbor"))).rejects.toThrow(
      /IssuerSigned is not valid CBOR/,
    );
  });

  it("rejects CBOR that does not match the IssuerSigned schema", async () => {
    await expect(validateMdoc(base64url.encode(encode({})))).rejects.toThrow(
      /IssuerSigned does not comply with schema/,
    );
  });

  it("runs namespace validation", async () => {
    await expect(
      validateMdoc(
        new TestMdocBuilder().withDuplicateItem("family_name").build(),
      ),
    ).rejects.toThrow(
      "Duplicate digest ID 10 in namespace org.test.namespace.2",
    );
  });

  it("runs issuerAuth validation", async () => {
    await expect(
      validateMdoc(
        new TestMdocBuilder().withProtectedHeader(new Map().set(1, 7)).build(),
      ),
    ).rejects.toThrow("dsadsa");
  });
});
