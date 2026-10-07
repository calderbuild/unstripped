// Off-chain inverse hints for P-384 certificate signatures (see tools/p384_hints.js, from
// base/nitro-validator). Only needed when the parent issuer's key is P-384.
import { createHash } from "crypto";
// @ts-ignore: plain CommonJS
import { collectVerifyHintBytes } from "../tools/p384_hints.js";

const pad = (v: Uint8Array, n: number) => {
  while (v.length > n && v[0] === 0) v = v.subarray(1);
  const out = new Uint8Array(n);
  out.set(v, n - v.length);
  return out;
};

/// r || s from a DER ECDSA signature, 48 bytes each.
function rs(der: Uint8Array) {
  const r0 = 4, rl = der[3];
  const s0 = r0 + rl + 2, sl = der[r0 + rl + 1];
  if (der[0] !== 0x30 || der[1] & 0x80) throw new Error("unexpected ECDSA signature encoding");
  return Buffer.concat([pad(der.subarray(r0, r0 + rl), 48), pad(der.subarray(s0, s0 + sl), 48)]);
}

/// Hints for verifying `sig` over `tbs` with a P-384 parent key (x || y, 96 bytes).
export function p384Hints(tbs: Uint8Array, sig: Uint8Array, parentKey: Uint8Array): Uint8Array {
  const h = createHash("sha384").update(tbs).digest();
  return collectVerifyHintBytes(h, rs(sig), Buffer.from(parentKey));
}

/// Arguments for addIssuer(cert under parent), with hints when the parent's key is P-384.
export async function addIssuerArgs(cc: { idOf: any; issuers: any }, cert: { tbs: Uint8Array; sig: Uint8Array }, parentTbs: Uint8Array) {
  const parent: string = await cc.idOf(parentTbs);
  const i = await cc.issuers(parent);
  const P384 = 3n;
  const hints = BigInt(i.keyType) === P384 ? p384Hints(cert.tbs, cert.sig, Buffer.from(i.key.slice(2), "hex")) : new Uint8Array();
  return [cert.tbs, cert.sig, parent, hints] as const;
}
