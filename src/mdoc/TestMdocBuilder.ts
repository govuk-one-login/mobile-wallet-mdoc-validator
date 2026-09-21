import {
  createHash,
  createPrivateKey,
  createSign,
  X509Certificate,
} from "node:crypto";
import { encode, Tag } from "cbor2";
import { base64url } from "jose";
import { TAGS } from "./constants/tags";
import {
  COSE_ALGORITHMS,
  COSE_ELLIPTIC_CURVES,
  COSE_HEADER_PARAMETERS,
  COSE_KEY_PARAMETERS,
  COSE_KEY_TYPES,
} from "./constants/cose";
import { IssuerSignedItem } from "./schemas/issuerSignedItemSchema";
import { IssuerSigned, issuerSignedSchema } from "./schemas/issuerSignedSchema";
import { parseSchema } from "./parseSchema";
import { decodeCbor } from "./decodeCbor";

export class TestMdocBuilder {
  private readonly namespaces: Map<string, IssuerSignedItem[]>;
  private readonly validityInfo: {
    signed: Tag | string;
    validFrom: Tag | string;
    validUntil: Tag | string;
    expectedUpdate?: Tag | string;
  };
  private readonly deviceKey: Map<unknown, unknown>;
  private readonly protectedHeader: Map<unknown, unknown>;
  private readonly unprotectedHeader: Map<unknown, unknown>;

  private readonly elementsWithMismatchedDigests: Map<string, Uint8Array>;
  private readonly elementsWithoutDigests: Set<string>;

  constructor() {
    this.namespaces = new Map();
    for (const [namespace, items] of DEFAULT_NAMESPACES) {
      this.namespaces.set(
        namespace,
        items.map((item) => ({ ...item })),
      );
    }

    this.validityInfo = {
      signed: new Tag(TAGS.DATE_TIME, "2025-09-10T15:20:00Z"),
      validFrom: new Tag(TAGS.DATE_TIME, "2025-09-10T15:20:00Z"),
      validUntil: new Tag(TAGS.DATE_TIME, "2026-09-10T15:20:00Z"),
    };

    this.deviceKey = new Map<unknown, unknown>(DEFAULT_DEVICE_KEY);

    this.protectedHeader = new Map<unknown, unknown>().set(
      COSE_HEADER_PARAMETERS.ALG,
      COSE_ALGORITHMS.ES256,
    );

    const documentSigningCertificate = new X509Certificate(
      DEFAULT_DOCUMENT_SIGNING_CERTIFICATE,
    );
    this.unprotectedHeader = new Map<unknown, unknown>().set(
      COSE_HEADER_PARAMETERS.X5_CHAIN,
      new Uint8Array(documentSigningCertificate.raw),
    );

    this.elementsWithoutDigests = new Set<string>();
    this.elementsWithMismatchedDigests = new Map<string, Uint8Array>();
  }

  build() {
    const valueDigests: Record<string, Map<number, Uint8Array>> = {};
    const nameSpacesEncoded: Record<string, (Tag | Uint8Array)[]> = {};

    for (const [namespace, items] of this.namespaces) {
      valueDigests[namespace] = new Map();
      nameSpacesEncoded[namespace] = [];

      for (const item of items) {
        const itemEncoded = encode(item);
        const taggedItem = new Tag(TAGS.ENCODED_CBOR_DATA, itemEncoded);

        nameSpacesEncoded[namespace].push(taggedItem);

        if (this.elementsWithoutDigests.has(item.elementIdentifier)) {
          continue;
        }

        const digestOverride = this.elementsWithMismatchedDigests.get(
          item.elementIdentifier,
        );
        if (digestOverride) {
          valueDigests[namespace].set(item.digestID, digestOverride);
        } else {
          const digest = createHash("sha256")
            .update(encode(taggedItem))
            .digest();
          valueDigests[namespace].set(item.digestID, new Uint8Array(digest));
        }
      }
    }

    const mso = {
      version: "1.0",
      digestAlgorithm: "SHA-256",
      valueDigests,
      deviceKeyInfo: {
        deviceKey: this.deviceKey,
        keyAuthorizations: {
          nameSpaces: Array.from(this.namespaces.keys()),
        },
      },
      docType: "org.test.document",
      status: {
        status_list: { idx: 1, uri: "https://example-status-list.com" },
      },
      validityInfo: {
        signed: this.validityInfo.signed,
        validFrom: this.validityInfo.validFrom,
        validUntil: this.validityInfo.validUntil,
        ...(this.validityInfo.expectedUpdate && {
          expectedUpdate: this.validityInfo.expectedUpdate,
        }),
      },
    };

    const msoBytes = encode(mso);
    const payload = encode(new Tag(TAGS.ENCODED_CBOR_DATA, msoBytes));

    const protectedHeader = encode(this.protectedHeader);
    const toBeSigned = encode([
      "Signature1",
      protectedHeader,
      new Uint8Array(),
      payload,
    ]);

    const signer = createSign("sha256");
    signer.update(toBeSigned);

    const signingKey = createPrivateKey({
      key: DEFAULT_SIGNING_KEY,
      type: "pkcs8",
      format: "pem",
    });

    const signature = signer.sign({
      key: signingKey,
      dsaEncoding: "ieee-p1363",
    });

    const issuerAuth = [
      protectedHeader,
      this.unprotectedHeader,
      payload,
      new Uint8Array(signature),
    ];

    const result = {
      nameSpaces: nameSpacesEncoded,
      issuerAuth,
    };

    return base64url.encode(encode(result));
  }

  buildIssuerSigned(): IssuerSigned {
    return parseSchema(
      issuerSignedSchema,
      decodeCbor(base64url.decode(this.build()), "IssuerSigned"),
      "IssuerSigned",
    );
  }

  withoutDigest(elementIdentifier: string) {
    this.elementsWithoutDigests.add(elementIdentifier);
    return this;
  }

  withMismatchedDigest(
    elementIdentifier: string,
    mismatchedDigest: Uint8Array,
  ) {
    this.elementsWithMismatchedDigests.set(elementIdentifier, mismatchedDigest);
    return this;
  }

  withValidityInfo(
    validityInfo: Partial<{
      signed: Tag | string;
      validFrom: Tag | string;
      validUntil: Tag | string;
      expectedUpdate: Tag | string;
    }>,
  ) {
    Object.assign(this.validityInfo, validityInfo);
    return this;
  }

  withDeviceKeyParameter(key: unknown, value: unknown): this {
    this.deviceKey.set(key, value);
    return this;
  }

  withProtectedHeader(protectedHeader: Map<unknown, unknown>) {
    this.protectedHeader.clear();
    for (const [key, value] of protectedHeader) {
      this.protectedHeader.set(key, value);
    }
    return this;
  }

  withUnprotectedHeader(unprotectedHeader: Map<unknown, unknown>) {
    this.unprotectedHeader.clear();
    for (const [key, value] of unprotectedHeader) {
      this.unprotectedHeader.set(key, value);
    }
    return this;
  }

  withMismatchedSigningCertificate(): this {
    return this.withUnprotectedHeader(
      new Map().set(
        COSE_HEADER_PARAMETERS.X5_CHAIN,
        new Uint8Array(UNRELATED_SIGNING_CERTIFICATE.raw),
      ),
    );
  }

  withDuplicateItem(elementIdentifier: string): this {
    for (const items of this.namespaces.values()) {
      const item = items.find((i) => i.elementIdentifier === elementIdentifier);
      if (item) {
        items.push({ ...item });
        return this;
      }
    }
    throw new Error(`No item with element identifier ${elementIdentifier}`);
  }
}

const DEFAULT_NAMESPACES = new Map([
  [
    "org.test.namespace.1",
    [
      {
        digestID: 90,
        random: new Uint8Array([
          9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ]),
        elementIdentifier: "portrait",
        elementValue: new Uint8Array([255, 216, 255, 224, 255, 217]),
      },
      {
        digestID: 40,
        random: new Uint8Array([
          3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        ]),
        elementIdentifier: "title",
        elementValue: "Mr",
      },
    ],
  ],
  [
    "org.test.namespace.2",
    [
      {
        digestID: 10,
        random: new Uint8Array([
          16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]),
        elementIdentifier: "family_name",
        elementValue: "Doe",
      },
      {
        digestID: 20,
        random: new Uint8Array([
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]),
        elementIdentifier: "given_name",
        elementValue: "Jane",
      },
      {
        digestID: 30,
        random: new Uint8Array([
          2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ]),
        elementIdentifier: "issue_date",
        elementValue: new Tag(TAGS.DATE_TIME, "2020-01-01T00:00:00Z"),
      },
    ],
  ],
]);

const DEFAULT_SIGNING_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKexbdPE2TDYzOuasfwN4QWNqHF1wNsV30ERMPPaRYnWoAoGCCqGSM49
AwEHoUQDQgAE+NKi4QpYV/avqTFFoldRIYEZaRgKF/qv+xJsek63Eh2cKn922zlJ
Hj2KglzSlLm439BfFYGDYVet6W7pkvIYfg==
-----END EC PRIVATE KEY-----`;

const DEFAULT_DOCUMENT_SIGNING_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBtzCCAV2gAwIBAgIUZpfeB6WGkUsUk13SiJX8i6vG1IAwCgYIKoZIzj0EAwIw
QTELMAkGA1UEBhMCR0IxMjAwBgNVBAMMKW1ETCBFeGFtcGxlIElBQ0EgUm9vdCAt
IExPQ0FMIGVudmlyb25tZW50MB4XDTI1MDkwMjEwMzMzMloXDTI2MDkwMjEwMzMz
MlowMjELMAkGA1UEBhMCR0IxIzAhBgNVBAMMGkV4YW1wbGUgSXNzdWVyIERTQyAo
TE9DQUwpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+NKi4QpYV/avqTFFoldR
IYEZaRgKF/qv+xJsek63Eh2cKn922zlJHj2KglzSlLm439BfFYGDYVet6W7pkvIY
fqNCMEAwHQYDVR0OBBYEFFBBWigj2hXjuJNidBxTFPvGxzOLMB8GA1UdIwQYMBaA
FPY4eri7CuGrxh14YMTQe1qnBVjoMAoGCCqGSM49BAMCA0gAMEUCIQCm99llHZfq
nPUS1X4/UZfbJ4HlbU33EaTqS/Y4vrOPVQIgLcG3k0jJQIxapcCUF7r/4rVUju0z
FmibH8pIONDZjSI=
-----END CERTIFICATE-----`;

// A valid certificate whose key did not sign the credential.
const UNRELATED_SIGNING_CERTIFICATE =
  new X509Certificate(`-----BEGIN CERTIFICATE-----
MIIB7TCCAZOgAwIBAgIUZpfeB6WGkUsUk13SiJX8i6vG1IEwCgYIKoZIzj0EAwIw
XDELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9u
MQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MQ0wCwYDVQQDDARUZXN0MB4X
DTI2MDEwODEzMzkzNVoXDTI3MDEwODEzMzkzNVowTTELMAkGA1UEBhMCVUsxDzAN
BgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ0wCwYDVQQKDARUZXN0MQ0w
CwYDVQQLDARUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+jfaNAHbEm+P
2QbR6EMOj7+nILxkSJIani1RIPJI2X/NTtwJbMq6TN7X7f9BtK5DsioNOThMF/+t
1EFaLFPAuKNCMEAwHQYDVR0OBBYEFL0/RS4sYeY0F/AvLmHbEEv9NSG4MB8GA1Ud
IwQYMBaAFOuameupM0YpmgBT5Q4WxFe6TVMUMAoGCCqGSM49BAMCA0gAMEUCIEBO
RlvvhrfRUeNSJ0B18SsHCw1r4YUoJ206JZPFWxsRAiEA39zuNQ4ituFpufYFAUzb
h6XK6xERRLkY5jjINTt8TkU=
-----END CERTIFICATE-----`);

const DEFAULT_DEVICE_KEY = new Map<number, number | Uint8Array>([
  [COSE_KEY_PARAMETERS.KTY, COSE_KEY_TYPES.EC2],
  [COSE_KEY_PARAMETERS.EC2_CRV, COSE_ELLIPTIC_CURVES.P_256],
  [
    COSE_KEY_PARAMETERS.EC2_X,
    new Uint8Array(
      Buffer.from(
        "6DCF397495962365F7E8FA912AB95D9990E9002E31CC151840FD7754AFA6BD53",
        "hex",
      ),
    ),
  ],
  [
    COSE_KEY_PARAMETERS.EC2_Y,
    new Uint8Array(
      Buffer.from(
        "39D569F97C102510B56506AE414A72D6EEAA084ED454C751DCF90FF9602C2953",
        "hex",
      ),
    ),
  ],
]);
