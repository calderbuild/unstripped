// Pulls what the ContentCredentials contract needs out of a file's embedded C2PA manifest.
// Pure byte work, no hashing or network, so it runs the same in Node and the browser.
// Supports PNG (caBX chunk) and JPEG (APP11 segments).

export type Credential = {
  issuer: string; // bytes32 issuer id, filled in by the caller (see issuerIdFor)
  leafTbs: Uint8Array;
  leafSig: Uint8Array;
  protectedHeader: Uint8Array;
  claim: Uint8Array;
  signature: Uint8Array;
  hashAssertion: Uint8Array;
  actionsAssertion: Uint8Array;
};

export type Extracted = {
  credential: Credential;
  chain: { tbs: Uint8Array; sig: Uint8Array }[]; // leaf first, as in the manifest's x5chain
  alg: number;
  stripped: Uint8Array; // the file with the manifest removed; sha256 of it is the asset hash
};

const ascii = (b: Uint8Array) => new TextDecoder().decode(b);
const u32 = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
const concat = (...xs: Uint8Array[]) => {
  const out = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let p = 0;
  for (const x of xs) (out.set(x, p), (p += x.length));
  return out;
};

// --- Containers ------------------------------------------------------------------------------
// Each returns the JUMBF manifest store and the byte ranges that hold it. Removing those ranges is
// exactly what C2PA's hard binding excludes, so sha256 of what is left is the signed asset hash.
type Found = { store: Uint8Array; cuts: [start: number, end: number][] };

function pngManifest(file: Uint8Array): Found {
  for (let p = 8; p < file.length; ) {
    const n = u32(file, p);
    if (ascii(file.subarray(p + 4, p + 8)) === "caBX") return { store: file.subarray(p + 8, p + 8 + n), cuts: [[p, p + 12 + n]] };
    p += 12 + n;
  }
  throw new Error("no C2PA manifest in this file");
}

/// JPEG keeps JUMBF in APP11 segments: "JP", box instance, sequence number, then the box. A box
/// split over several segments repeats its 8-byte header (16 with an extended length) in each.
function jpegManifest(file: Uint8Array): Found {
  const parts: Uint8Array[] = [];
  const cuts: [number, number][] = [];
  for (let p = 2; p + 4 <= file.length && file[p] === 0xff; ) {
    const marker = file[p + 1];
    if (marker === 0xda || marker === 0xd9) break; // image data starts: no more metadata
    const end = p + 2 + ((file[p + 2] << 8) | file[p + 3]);
    if (marker === 0xeb && file[p + 4] === 0x4a && file[p + 5] === 0x50) {
      const box = file.subarray(p + 12, end);
      const header = u32(box, 0) === 1 ? 16 : 8;
      parts.push(parts.length ? box.subarray(header) : box);
      cuts.push([p, end]);
    }
    p = end;
  }
  if (!parts.length) throw new Error("no C2PA manifest in this file");
  return { store: concat(...parts), cuts };
}

function findManifest(file: Uint8Array): Found {
  if (file[0] === 0x89 && ascii(file.subarray(1, 4)) === "PNG") return pngManifest(file);
  if (file[0] === 0xff && file[1] === 0xd8) return jpegManifest(file);
  throw new Error("only PNG and JPEG are supported");
}

const without = (file: Uint8Array, cuts: [number, number][]) => {
  const keep: Uint8Array[] = [];
  let p = 0;
  for (const [a, b] of cuts) (keep.push(file.subarray(p, a)), (p = b));
  return concat(...keep, file.subarray(p));
};

// --- JUMBF ---------------------------------------------------------------------------------
type Box = { type: string; raw: Uint8Array; body: Uint8Array };
function boxes(b: Uint8Array): Box[] {
  const out: Box[] = [];
  for (let p = 0; p < b.length; ) {
    let n = u32(b, p);
    let hdr = 8;
    if (n === 1) (n = Number(new DataView(b.buffer, b.byteOffset + p + 8, 8).getBigUint64(0)), (hdr = 16));
    out.push({ type: ascii(b.subarray(p + 4, p + 8)), raw: b.subarray(p, p + n), body: b.subarray(p + hdr, p + n) });
    p += n;
  }
  return out;
}
type Node = { label: string; boxes: Box[]; children: Node[] };
function superbox(body: Uint8Array): Node {
  const bs = boxes(body);
  if (bs[0]?.type !== "jumd") throw new Error("bad JUMBF superbox");
  const desc = bs[0].body.subarray(17);
  const label = ascii(desc.subarray(0, desc.indexOf(0)));
  return { label, boxes: bs, children: bs.filter((x) => x.type === "jumb").map((x) => superbox(x.body)) };
}
const child = (n: Node, label: string) => {
  const c = n.children.find((x) => x.label === label);
  if (!c) throw new Error(`manifest has no ${label}`);
  return c;
};
const content = (n: Node) => n.boxes[1].body; // the box after jumd
const superboxBytes = (n: Node) => concat(n.boxes[0].raw, n.boxes[1].raw); // what the claim hashes

// --- CBOR (just enough for COSE_Sign1) --------------------------------------------------------
function head(b: Uint8Array, p: number): [mt: number, v: number, q: number] {
  const ib = b[p];
  const ai = ib & 31;
  let q = p + 1;
  let v = ai;
  if (ai === 24) v = b[q++];
  else if (ai === 25) (v = (b[q] << 8) | b[q + 1]), (q += 2);
  else if (ai === 26) (v = u32(b, q)), (q += 4);
  else if (ai > 26) throw new Error("unsupported CBOR length");
  return [ib >> 5, v, q];
}
function item(b: Uint8Array, p: number): [value: unknown, next: number] {
  const [mt, v, q] = head(b, p);
  if (mt === 0) return [v, q];
  if (mt === 1) return [-1 - v, q];
  if (mt === 2) return [b.subarray(q, q + v), q + v];
  if (mt === 3) return [ascii(b.subarray(q, q + v)), q + v];
  if (mt === 6) return item(b, q);
  if (mt === 7) return [null, q];
  const arr: unknown[] = [];
  let r = q;
  for (let i = 0; i < (mt === 5 ? 2 * v : v); i++) {
    const [x, n] = item(b, r);
    arr.push(x);
    r = n;
  }
  if (mt === 4) return [arr, r];
  const m = new Map<unknown, unknown>();
  for (let i = 0; i < arr.length; i += 2) m.set(arr[i], arr[i + 1]);
  return [m, r];
}

// --- DER: split a certificate into TBS and signature --------------------------------------------
function der(b: Uint8Array, p: number): [start: number, end: number] {
  let len = b[p + 1];
  let s = p + 2;
  if (len & 0x80) {
    const nb = len & 0x7f;
    len = 0;
    for (let i = 0; i < nb; i++) len = len * 256 + b[p + 2 + i];
    s += nb;
  }
  return [s, s + len];
}
export function splitCert(cert: Uint8Array) {
  const [s] = der(cert, 0);
  const [, tbsEnd] = der(cert, s);
  const [, algEnd] = der(cert, tbsEnd);
  const [bs, be] = der(cert, algEnd);
  return { tbs: cert.subarray(s, tbsEnd), sig: cert.subarray(bs + 1, be) };
}

/// Raw DER of a TBS certificate's issuer and subject names, to find a certificate's parent.
export function names(tbs: Uint8Array) {
  let [p] = der(tbs, 0);
  if (tbs[p] === 0xa0) p = der(tbs, p)[1]; // version
  p = der(tbs, p)[1]; // serial
  p = der(tbs, p)[1]; // signature algorithm
  const [, issuerEnd] = der(tbs, p);
  const issuer = tbs.subarray(p, issuerEnd);
  const [, validityEnd] = der(tbs, issuerEnd);
  const subject = tbs.subarray(validityEnd, der(tbs, validityEnd)[1]);
  return { issuer, subject };
}

export function extract(file: Uint8Array): Extracted {
  const m = findManifest(file);
  const store = superbox(boxes(m.store)[0].body);
  const manifest = store.children[store.children.length - 1]; // the active manifest is the last one
  const claimNode = manifest.children.find((x) => x.label.startsWith("c2pa.claim"));
  if (!claimNode) throw new Error("manifest has no claim");
  const [cose] = item(content(child(manifest, "c2pa.signature")), 0) as [unknown[], number];
  const [protectedHeader, unprotected, , signature] = cose as [Uint8Array, Map<unknown, unknown>, null, Uint8Array];
  const [ph] = item(protectedHeader, 0) as [Map<unknown, unknown>, number];
  let x5 = (ph.get(33) ?? unprotected.get(33)) as Uint8Array | Uint8Array[];
  if (x5 instanceof Uint8Array) x5 = [x5];
  const chain = x5.map(splitCert);
  const assertions = child(manifest, "c2pa.assertions");
  const actions = assertions.children.find((x) => x.label === "c2pa.actions.v2" || x.label === "c2pa.actions");
  return {
    credential: {
      issuer: "0x" + "00".repeat(32),
      leafTbs: chain[0].tbs,
      leafSig: chain[0].sig,
      protectedHeader,
      claim: content(claimNode),
      signature,
      hashAssertion: superboxBytes(child(assertions, "c2pa.hash.data")),
      actionsAssertion: actions ? superboxBytes(actions) : new Uint8Array(),
    },
    chain,
    alg: ph.get(1) as number,
    stripped: without(file, m.cuts),
  };
}

/// Removes the embedded manifest, like a platform that strips metadata would.
export function strip(file: Uint8Array): Uint8Array {
  return extract(file).stripped;
}
