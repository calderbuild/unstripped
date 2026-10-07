// Read side of the registry, shared by the web app, the relayer and scripts.
import { Contract, ContractRunner, sha256, hexlify } from "ethers";
import { extract, Extracted } from "./c2pa";

export const ABI = [
  "function register((bytes32 issuer, bytes leafTbs, bytes leafSig, bytes protectedHeader, bytes claim, bytes signature, bytes hashAssertion, bytes actionsAssertion) c) returns (bytes32)",
  "function provenanceOf(bytes32) view returns ((bytes32 issuer, bytes32 claimHash, address registrant, uint64 registeredAt, int16 alg, bool aiGenerated, string signerOrg, string signerName, string generator, string sourceType))",
  "function isRegistered(bytes32) view returns (bool)",
  "function isAIGenerated(bytes32) view returns (bool)",
  "function idOf(bytes tbs) view returns (bytes32)",
  "function issuers(bytes32) view returns (uint8 keyType, bytes rsaModulus, bytes32 x, bytes32 y, bytes32 parent, string org, string cn)",
  "function assetCount() view returns (uint256)",
  "function assets(uint256) view returns (bytes32)",
  "error UnknownIssuer(bytes32 issuer)",
  "error BadCertSignature()",
  "error UnsupportedAlg(int256 alg)",
  "error BadClaimSignature()",
  "error MissingAssertion(string name)",
  "error AssertionMismatch(string name)",
  "event Registered(bytes32 indexed assetHash, bytes32 indexed issuer, address indexed registrant, string signerOrg, bool aiGenerated)",
];

export type Provenance = {
  issuer: string;
  claimHash: string;
  registrant: string;
  registeredAt: number;
  alg: number;
  aiGenerated: boolean;
  signerOrg: string;
  signerName: string;
  generator: string;
  sourceType: string;
};

export const registry = (address: string, runner: ContractRunner) => new Contract(address, ABI, runner);

const toProvenance = (r: any): Provenance => ({
  issuer: r.issuer,
  claimHash: r.claimHash,
  registrant: r.registrant,
  registeredAt: Number(r.registeredAt),
  alg: Number(r.alg),
  aiGenerated: r.aiGenerated,
  signerOrg: r.signerOrg,
  signerName: r.signerName,
  generator: r.generator,
  sourceType: r.sourceType,
});

export async function provenanceOf(c: Contract, assetHash: string): Promise<Provenance | null> {
  const r = await c.provenanceOf(assetHash);
  return Number(r.registeredAt) === 0 ? null : toProvenance(r);
}

export type Lookup = {
  assetHash: string; // the hash the registry is keyed by
  hadManifest: boolean;
  extracted: Extracted | null;
  extractError: string | null;
  provenance: Provenance | null;
};

/// What the registry knows about a file. A file that still carries its manifest is keyed by the
/// hash of its stripped form; a file without one is assumed to be a stripped copy already.
export async function lookup(c: Contract, file: Uint8Array): Promise<Lookup> {
  let extracted: Extracted | null = null;
  let extractError: string | null = null;
  try {
    extracted = extract(file);
  } catch (e) {
    extractError = (e as Error).message;
  }
  const assetHash = sha256(extracted ? extracted.stripped : file);
  return { assetHash, hadManifest: !!extracted, extracted, extractError, provenance: await provenanceOf(c, assetHash) };
}

/// The issuer to register under: the signing certificate itself if it is a pinned anchor,
/// otherwise the first certificate up the chain that the registry knows.
export async function resolveIssuer(c: Contract, x: Extracted): Promise<string | null> {
  for (const cert of x.chain) {
    // idOf reverts for keys the registry cannot use (P-384 CAs, for one); those can't be anchors.
    const id: string | null = await c.idOf(cert.tbs).catch(() => null);
    if (id && Number((await c.issuers(id)).keyType) !== 0) return id;
  }
  return null;
}

/// Credential as hex strings, the shape the relayer accepts and ethers encodes.
export function credentialJSON(x: Extracted, issuer: string) {
  const k = x.credential;
  return {
    issuer,
    leafTbs: hexlify(k.leafTbs),
    leafSig: hexlify(k.leafSig),
    protectedHeader: hexlify(k.protectedHeader),
    claim: hexlify(k.claim),
    signature: hexlify(k.signature),
    hashAssertion: hexlify(k.hashAssertion),
    actionsAssertion: hexlify(k.actionsAssertion),
  };
}
