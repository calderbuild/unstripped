import { expect } from "chai";
import { ethers } from "hardhat";
import { readFileSync } from "fs";
import { extract, splitCert, Credential } from "../sdk/c2pa";
import { addIssuerArgs } from "../sdk/hints";
import { onboard } from "../api/register";
import { chainJSON } from "../sdk/registry";

const openai = extract(readFileSync("fixtures/openai.png"));
const gemini = extract(readFileSync("fixtures/gemini.png"));
const OPENAI_ASSET = "0xdff2d1f58ef9566578bd8129c6659a16a19e6b81da7fa5c57515494e394020b5"; // from c2pa-python

const trufo = extract(readFileSync("fixtures/openai-trufo.png"));
const jpegFile = readFileSync("fixtures/openai.jpg");
const jpeg = extract(jpegFile);

/// The same JPEG with its manifest box split over two APP11 segments, as large manifests are.
function splitApp11(file: Buffer): Buffer {
  const p = 20; // APP0 (JFIF) is 18 bytes, then the APP11 marker
  const len = file.readUInt16BE(p + 2);
  const head = file.subarray(p + 4, p + 12); // "JP", instance, sequence
  const box = file.subarray(p + 12, p + 2 + len);
  const cut = 5000;
  const seg = (body: Buffer) => Buffer.concat([Buffer.from([0xff, 0xeb]), Buffer.from([(body.length + 2) >> 8, (body.length + 2) & 255]), body]);
  const second = Buffer.concat([head.subarray(0, 4), Buffer.from([0, 0, 0, 2]), box.subarray(0, 8), box.subarray(cut)]);
  return Buffer.concat([file.subarray(0, p), seg(Buffer.concat([head, box.subarray(0, cut)])), seg(second), file.subarray(p + 2 + len)]);
}
const root = (f: string) => splitCert(readFileSync(`fixtures/roots/${f}.der`)).tbs;
const ROOTS = ["sslcom-c2pa-rsa-root-2025", "trufo-c2pa-root-2025-p384", "google-c2pa-root-g3"].map(root);

/// Anchors are the three C2PA roots. Everything below them is added permissionlessly by `other`
/// and verified on chain: RSA (SSL.com), and P-384 in Solidity (Trufo, Google).
const logged = new Set<string>();
async function deploy() {
  const [deployer, other] = await ethers.getSigners();
  const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
  for (const r of ROOTS) await cc.addAnchor(r);
  await cc.seal();
  const add = async (cert: { tbs: Uint8Array; sig: Uint8Array }, parentTbs: Uint8Array, label: string) => {
    const tx = await cc.connect(other).addIssuer(...(await addIssuerArgs(cc, cert, parentTbs)));
    const gas = (await tx.wait())!.gasUsed;
    if (!logged.has(label)) (logged.add(label), console.log(`      addIssuer ${label} gas: ${gas}`));
  };
  await add(openai.chain[1], ROOTS[0], "SSL.com ICA (RSA-4096 root)");
  await add(trufo.chain[1], ROOTS[1], "Trufo ICA (P-384 root)");
  await add(trufo.chain[0], trufo.chain[1].tbs, "OpenAI leaf under Trufo (P-384 ICA)");
  await add(gemini.chain[1], ROOTS[2], "Google ICA (P-384 root)");
  await add(gemini.chain[0], gemini.chain[1].tbs, "Google leaf (P-384 ICA)");
  const openaiCred = { ...openai.credential, issuer: await cc.idOf(openai.chain[1].tbs) };
  const geminiCred = { ...gemini.credential, issuer: await cc.idOf(gemini.chain[0].tbs) };
  return { cc, deployer, other, openaiCred, geminiCred };
}

const flip = (b: Uint8Array, i: number) => {
  const c = Uint8Array.from(b);
  c[i] ^= 1;
  return c;
};

describe("ContentCredentials", () => {
  it("verifies OpenAI's PS256 credential and records the stripped file's hash", async () => {
    const { cc, other, openaiCred } = await deploy();
    expect(ethers.sha256(openai.stripped)).to.equal(OPENAI_ASSET);
    const tx = await cc.connect(other).register(openaiCred);
    const gas = (await tx.wait())!.gasUsed;
    console.log(`      register (PS256 + RSA-4096 chain) gas: ${gas}`);
    const r = await cc.provenanceOf(OPENAI_ASSET);
    expect(r.signerOrg).to.equal("OpenAI OpCo, LLC");
    expect(r.signerName).to.equal("OpenAI Media Service");
    expect(r.generator).to.equal("OpenAI Media Service API");
    expect(r.alg).to.equal(-37);
    expect(r.aiGenerated).to.equal(true);
    expect(r.registrant).to.equal(other.address);
  });

  it("verifies Google's ES256 credential through the P256 precompile", async () => {
    const { cc, geminiCred } = await deploy();
    const tx = await cc.register(geminiCred);
    console.log(`      register (ES256, pinned signer) gas: ${(await tx.wait())!.gasUsed}`);
    const r = await cc.provenanceOf(ethers.sha256(gemini.stripped));
    expect(r.signerOrg).to.equal("Google LLC");
    expect(r.alg).to.equal(-7);
    expect(r.aiGenerated).to.equal(true);
    console.log(`      gemini sourceType: ${r.sourceType}, generator: ${r.generator}`);
  });

  it("relayer onboards a signer it has not seen (a rotated certificate) before registering", async () => {
    const [, other] = await ethers.getSigners();
    const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
    for (const r of ROOTS) await cc.addAnchor(r);
    await cc.seal();
    await cc.addIssuer(...(await addIssuerArgs(cc, gemini.chain[1], ROOTS[2]))); // Google's ICA only
    const added = await onboard(cc.connect(other), chainJSON(gemini));
    expect(added.length).to.equal(1);
    await cc.register({ ...gemini.credential, issuer: await cc.idOf(gemini.chain[0].tbs) });
    expect(await cc.isAIGenerated(ethers.sha256(gemini.stripped))).to.equal(true);
  });

  it("relayer onboards a whole chain whose root is not in the manifest (OpenAI via Trufo)", async () => {
    const [, other] = await ethers.getSigners();
    const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
    for (const r of ROOTS) await cc.addAnchor(r);
    await cc.seal();
    const added = await onboard(cc.connect(other), chainJSON(trufo)); // ICA under the trust-list root, then the leaf
    expect(added.length).to.equal(2);
    await cc.register({ ...trufo.credential, issuer: await cc.idOf(trufo.chain[0].tbs) });
    expect((await cc.provenanceOf(ethers.sha256(trufo.stripped))).signerOrg).to.equal("OpenAI OpCo, LLC");
  });

  it("reads JPEG: verifies OpenAI's credential from APP11 and records the stripped file's hash", async () => {
    const { cc } = await deploy();
    await cc.register({ ...jpeg.credential, issuer: await cc.idOf(jpeg.chain[1].tbs) }); // PS256 under the SSL.com ICA
    const r = await cc.provenanceOf(ethers.sha256(jpeg.stripped));
    expect(r.signerOrg).to.equal("OpenAI OpCo, LLC");
    expect(r.aiGenerated).to.equal(true);
    expect(jpeg.stripped.length).to.be.lessThan(jpegFile.length);
  });

  it("rejects a manifest box with a bad length instead of looping", () => {
    const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const chunk = Buffer.concat([Buffer.from([0, 0, 0, 8]), Buffer.from("caBX"), Buffer.alloc(8), Buffer.alloc(4)]);
    expect(() => extract(Buffer.concat([sig, chunk]))).to.throw();
  });

  it("reads a JPEG manifest split over several APP11 segments", () => {
    const x = extract(splitApp11(jpegFile));
    expect(Buffer.from(x.credential.claim)).to.deep.equal(Buffer.from(jpeg.credential.claim));
    expect(ethers.sha256(x.stripped)).to.equal(ethers.sha256(jpeg.stripped));
  });

  it("LabeledFeed labels a post from the registry, stripped copy included", async () => {
    const { cc, openaiCred } = await deploy();
    await cc.register(openaiCred);
    const feed = await (await ethers.getContractFactory("LabeledFeed")).deploy(await cc.getAddress());
    await feed.post(ethers.sha256(openai.stripped), "ipfs://lighthouse");
    await feed.post(ethers.sha256(readFileSync("fixtures/roots/google-c2pa-root-g3.der")), "ipfs://not-an-image");
    const [a, b] = [await feed.posts(0), await feed.posts(1)];
    expect([a.hasCredential, a.aiGenerated]).to.deep.equal([true, true]);
    expect([b.hasCredential, b.aiGenerated]).to.deep.equal([false, false]);
  });

  it("names a known signer from its verified certificate, not from the TBS the caller sends", async () => {
    const { cc } = await deploy();
    const tbs = Buffer.from(trufo.credential.leafTbs);
    const at = tbs.indexOf("OpenAI OpCo, LLC");
    expect(at).to.be.greaterThan(0);
    tbs.write("Fakeco OpCo, LLC", at); // same length, still valid DER, same key
    await cc.register({ ...trufo.credential, leafTbs: tbs, issuer: await cc.idOf(trufo.chain[0].tbs) });
    expect((await cc.provenanceOf(ethers.sha256(trufo.stripped))).signerOrg).to.equal("OpenAI OpCo, LLC");
  });

  it("is idempotent: a second registration keeps the first registrant", async () => {
    const { cc, other, openaiCred } = await deploy();
    await cc.register(openaiCred);
    await cc.connect(other).register(openaiCred);
    expect(await cc.assetCount()).to.equal(1);
  });

  describe("rejects", () => {
    const cases: [string, (c: Credential) => Credential, string][] = [
      ["a claim changed after signing", (c) => ({ ...c, claim: flip(c.claim, 40) }), "BadClaimSignature"],
      ["a forged COSE signature", (c) => ({ ...c, signature: flip(c.signature, 10) }), "BadClaimSignature"],
      ["a hash assertion that is not the signed one", (c) => ({ ...c, hashAssertion: flip(c.hashAssertion, c.hashAssertion.length - 3) }), "AssertionMismatch"],
      ["an actions assertion that is not the signed one", (c) => ({ ...c, actionsAssertion: flip(c.actionsAssertion, c.actionsAssertion.length - 3) }), "AssertionMismatch"],
      ["a signing certificate the CA did not sign", (c) => ({ ...c, leafSig: flip(c.leafSig, 5) }), "BadCertSignature"],
      ["an unknown issuer", (c) => ({ ...c, issuer: ethers.ZeroHash }), "UnknownIssuer"],
    ];
    for (const [name, mutate, err] of cases) {
      it(name, async () => {
        const { cc, openaiCred } = await deploy();
        await expect(cc.register(mutate(openaiCred))).to.be.revertedWithCustomError(cc, err);
      });
    }

    it("a Google credential whose signer was never added", async () => {
      const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      const cred = { ...gemini.credential, issuer: await cc.idOf(gemini.chain[0].tbs) };
      await expect(cc.register(cred)).to.be.revertedWithCustomError(cc, "UnknownIssuer");
    });

    it("an issuer whose P-384 certificate signature is forged", async () => {
      const { cc, other } = await deploy();
      const fake = { ...trufo.chain[1], sig: flip(trufo.chain[1].sig, 20) };
      const fresh = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      for (const r of ROOTS) await fresh.addAnchor(r);
      await expect(fresh.connect(other).addIssuer(fake.tbs, fake.sig, await fresh.idOf(ROOTS[1]), "0x")).to.be.revertedWithCustomError(fresh, "BadCertSignature");
      void cc;
    });

    it("an issuer with a wrong P-384 inverse hint", async () => {
      const fresh = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      for (const r of ROOTS) await fresh.addAnchor(r);
      const [tbs, sig, parent, hints] = await addIssuerArgs(fresh, trufo.chain[1], ROOTS[1]);
      await expect(fresh.addIssuer(tbs, sig, parent, flip(hints, 7))).to.be.reverted;
    });

    it("an issuer signed by a different root than the one named", async () => {
      const { other } = await deploy();
      const fresh = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      for (const r of ROOTS) await fresh.addAnchor(r);
      await expect(fresh.connect(other).addIssuer(gemini.chain[1].tbs, gemini.chain[1].sig, await fresh.idOf(ROOTS[1]), "0x")).to.be.revertedWithCustomError(fresh, "BadCertSignature");
    });

    it("a forged Google ES256 signature", async () => {
      const { cc, geminiCred } = await deploy();
      await expect(cc.register({ ...geminiCred, signature: flip(geminiCred.signature, 3) })).to.be.revertedWithCustomError(cc, "BadClaimSignature");
    });

    it("new anchors after seal, and anchors from anyone but the deployer", async () => {
      const { cc, other } = await deploy();
      await expect(cc.addAnchor(openai.chain[0].tbs)).to.be.revertedWith("anchors sealed");
      const fresh = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      await expect(fresh.connect(other).addAnchor(openai.chain[0].tbs)).to.be.revertedWith("anchors sealed");
    });
  });
});
