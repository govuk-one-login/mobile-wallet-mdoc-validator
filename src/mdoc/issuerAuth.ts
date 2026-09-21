import { encode } from "cbor2";
import { createHash, KeyObject, verify, X509Certificate } from "node:crypto";
import {
  MobileSecurityObject,
  mobileSecurityObjectSchema,
  ValidityInfo,
  ValueDigests,
} from "./schemas/mobileSecurityObjectSchema";
import { errorMessage, MdocValidationError } from "./MdocValidationError";
import { parseSchema } from "./parseSchema";
import { decodeCbor } from "./decodeCbor";
import { IssuerAuth, NameSpaces } from "./schemas/issuerSignedSchema";
import {
  COSE_ALGORITHMS,
  COSE_ELLIPTIC_CURVES,
  COSE_HEADER_PARAMETERS,
  COSE_KEY_PARAMETERS,
  COSE_KEY_TYPES,
} from "./constants/cose";
import { encodedDataTag } from "./schemas/cborTags";
import { issuerSignedItemSchema } from "./schemas/issuerSignedItemSchema";

export async function validateIssuerAuth(
  issuerAuth: IssuerAuth,
  nameSpaces: NameSpaces,
): Promise<void> {
  const [protectedHeader, unprotectedHeader, payload, signature] = issuerAuth; // COSE_Sign1

  validateProtectedHeader(protectedHeader);
  const certificate = validateUnprotectedHeader(unprotectedHeader);

  // Everything below operates on the MSO, so the signature must be verified first.
  verifySignature(certificate.publicKey, protectedHeader, payload, signature);

  const mso = parseMobileSecurityObject(payload);
  validateValidityInfo(mso.validityInfo);
  validateDigestsMatchMso(mso.valueDigests, nameSpaces);
  await validateDeviceKey(mso.deviceKeyInfo.deviceKey);
}

function validateProtectedHeader(protectedHeader: Uint8Array): void {
  const protectedHeaderDecoded = decodeCbor(
    protectedHeader,
    "Protected header",
  );

  if (!(protectedHeaderDecoded instanceof Map)) {
    throw new MdocValidationError(
      "Protected header is not a Map",
      "INVALID_PROTECTED_HEADER",
    );
  }

  if (protectedHeaderDecoded.size !== 1) {
    throw new MdocValidationError(
      "Protected header contains unexpected extra parameters",
      "INVALID_PROTECTED_HEADER",
    );
  }

  if (!protectedHeaderDecoded.has(COSE_HEADER_PARAMETERS.ALG)) {
    throw new MdocValidationError(
      'Protected header missing "alg" (1)',
      "INVALID_PROTECTED_HEADER",
    );
  }

  if (
    protectedHeaderDecoded.get(COSE_HEADER_PARAMETERS.ALG) !==
    COSE_ALGORITHMS.ES256
  ) {
    throw new MdocValidationError(
      'Protected header "alg" must be -7 (ES256)',
      "INVALID_PROTECTED_HEADER",
    );
  }
}

function validateUnprotectedHeader(
  unprotectedHeader: Map<number, Uint8Array>,
): X509Certificate {
  if (unprotectedHeader.size !== 1) {
    throw new MdocValidationError(
      "Unprotected header contains unexpected extra parameters",
      "INVALID_UNPROTECTED_HEADER",
    );
  }
  const x5chain = unprotectedHeader.get(COSE_HEADER_PARAMETERS.X5_CHAIN);

  if (x5chain === undefined) {
    throw new MdocValidationError(
      'Unprotected header missing "x5chain" (33)',
      "INVALID_UNPROTECTED_HEADER",
    );
  }

  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(x5chain);
  } catch (error) {
    throw new MdocValidationError(
      `Failed to parse document signing certificate as X509Certificate - ${errorMessage(error)}`,
      "INVALID_UNPROTECTED_HEADER",
    );
  }

  return certificate;
}

function verifySignature(
  publicKey: KeyObject,
  protectedHeader: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): void {
  const sigStructure = [
    "Signature1",
    protectedHeader,
    new Uint8Array(),
    payload,
  ];

  const toBeSigned = encode(sigStructure);
  try {
    const outcome = verify(
      "sha256",
      toBeSigned,
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );

    if (!outcome) {
      throw new MdocValidationError(
        "Signature not verified",
        "INVALID_SIGNATURE",
      );
    }
  } catch (error) {
    if (error instanceof MdocValidationError) {
      throw error;
    }
    throw new MdocValidationError(
      `Signature could not be verified - ${errorMessage(error)} `,
      "INVALID_SIGNATURE",
    );
  }
}

function parseMobileSecurityObject(payload: Uint8Array): MobileSecurityObject {
  const msoBytes = parseSchema(
    encodedDataTag,
    decodeCbor(payload, "MobileSecurityObjectBytes"),
    "MobileSecurityObjectBytes",
  );
  return parseSchema(
    mobileSecurityObjectSchema,
    decodeCbor(msoBytes.contents, "MobileSecurityObject"),
    "MobileSecurityObject",
  );
}

// Every presented item in nameSpaces must match an MSO digest.
// MSO digests with no presented item are expected — that's selective disclosure.
function validateDigestsMatchMso(
  valueDigests: ValueDigests,
  nameSpaces: NameSpaces,
): void {
  for (const [namespace, items] of Object.entries(nameSpaces)) {
    const msoDigests = valueDigests[namespace];
    if (!msoDigests) {
      throw new MdocValidationError(
        `No digests found for namespace ${namespace}`,
        "INVALID_DIGESTS",
      );
    }

    for (const taggedIssuerSignedItemBytes of items) {
      const calculatedDigest = createHash("sha256")
        .update(encode(taggedIssuerSignedItemBytes))
        .digest();

      const issuedSignedItem = parseSchema(
        issuerSignedItemSchema,
        decodeCbor(taggedIssuerSignedItemBytes.contents, "IssuerSignedItem"),
        "IssuerSignedItem",
      );
      const digestID = issuedSignedItem.digestID;

      const expectedDigest = msoDigests.get(digestID);
      if (expectedDigest === undefined) {
        throw new MdocValidationError(
          `No digest found for digest ID ${digestID.toString()} in MSO namespace ${namespace}`,
          "INVALID_DIGESTS",
        );
      }
      if (!calculatedDigest.equals(Buffer.from(expectedDigest))) {
        throw new MdocValidationError(
          `Digest mismatch for element identifier ${issuedSignedItem.elementIdentifier} with digest ID ${digestID.toString()} in namespace ${namespace}`,
          "INVALID_DIGESTS",
        );
      }
    }
  }
}

async function validateDeviceKey(
  deviceKey: Map<unknown, unknown>,
): Promise<void> {
  const requiredKeys = [
    COSE_KEY_PARAMETERS.KTY,
    COSE_KEY_PARAMETERS.EC2_CRV,
    COSE_KEY_PARAMETERS.EC2_X,
    COSE_KEY_PARAMETERS.EC2_Y,
  ];
  const keys = new Set(deviceKey.keys());

  if (
    keys.size !== requiredKeys.length ||
    requiredKeys.some((k) => !keys.has(k))
  ) {
    throw new MdocValidationError(
      "DeviceKey must contain exactly the keys [1, -1, -2, -3]",
      "INVALID_DEVICE_KEY",
    );
  }

  if (deviceKey.get(COSE_KEY_PARAMETERS.KTY) !== COSE_KEY_TYPES.EC2) {
    throw new MdocValidationError(
      "DeviceKey key type (1) must be EC2 (Elliptic Curve) (2)",
      "INVALID_DEVICE_KEY",
    );
  }

  if (
    deviceKey.get(COSE_KEY_PARAMETERS.EC2_CRV) !== COSE_ELLIPTIC_CURVES.P_256
  ) {
    throw new MdocValidationError(
      "DeviceKey curve (-1) must be P-256 (1)",
      "INVALID_DEVICE_KEY",
    );
  }
  const x = deviceKey.get(COSE_KEY_PARAMETERS.EC2_X);
  const y = deviceKey.get(COSE_KEY_PARAMETERS.EC2_Y);

  if (!(x instanceof Uint8Array)) {
    throw new MdocValidationError(
      "DeviceKey x-coordinate (-2) must be a Uint8Array",
      "INVALID_DEVICE_KEY",
    );
  }
  if (!(y instanceof Uint8Array)) {
    throw new MdocValidationError(
      "DeviceKey y-coordinate (-3) must be a Uint8Array",
      "INVALID_DEVICE_KEY",
    );
  }

  try {
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(x).toString("base64url"),
      y: Buffer.from(y).toString("base64url"),
    };

    await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new MdocValidationError(
      `Invalid elliptic curve key`,
      "INVALID_DEVICE_KEY",
    );
  }
}

function validateValidityInfo(validityInfo: ValidityInfo): void {
  const errors: string[] = [];
  const now = new Date();

  const signed = validityInfo.signed.contents;
  const validFrom = validityInfo.validFrom.contents;
  const validUntil = validityInfo.validUntil.contents;

  const signedDate = new Date(signed);
  const validFromDate = new Date(validFrom);
  const validUntilDate = new Date(validUntil);

  if (signedDate > now) errors.push(`'signed' (${signed}) must be in the past`);
  if (validFromDate > now)
    errors.push(`'validFrom' (${validFrom}) must be in the past`);
  if (validUntilDate <= now)
    errors.push(`'validUntil' (${validUntil}) must be in the future`);
  if (validFromDate < signedDate)
    errors.push(
      `'validFrom' (${validFrom}) must be equal or later than 'signed' (${signed})`,
    );

  if (validityInfo.expectedUpdate) {
    const expectedUpdate = validityInfo.expectedUpdate.contents;
    const expectedUpdateDate = new Date(expectedUpdate);
    if (expectedUpdateDate > validUntilDate)
      errors.push(
        `'expectedUpdate' (${expectedUpdate}) must be less than or equal to 'validUntil' (${validUntil})`,
      );
  }

  if (errors.length !== 0) {
    throw new MdocValidationError(
      `One or more dates are invalid - ${errorMessage(errors)}`,
      "INVALID_VALIDITY_INFO",
    );
  }
}
