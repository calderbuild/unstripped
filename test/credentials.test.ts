import { expect } from "chai";
import { ethers } from "hardhat";
import { readFileSync } from "fs";
import { extract, Credential } from "../sdk/c2pa";

const openai = extract(readFileSync("fixtures/openai.png"));
const gemini = extract(readFileSync("fixtures/gemini.png"));
const OPENAI_ASSET = "0xdff2d1f58ef9566578bd8129c6659a16a19e6b81da7fa5c57515494e394020b5"; // from c2pa-python

async function deploy() {
  const [deployer, other] = await ethers.getSigners();
  const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
  await cc.addAnchor(openai.chain[1].tbs); // SSL.com C2PA ICA R1 2025 (RSA-4096)
  await cc.addAnchor(gemini.chain[0].tbs); // Google Media Processing Services, pinned (its CA is P-384)
  await cc.seal();
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

    it("a Google credential whose pinned signer was never anchored", async () => {
      const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
      const cred = { ...gemini.credential, issuer: await cc.idOf(gemini.chain[0].tbs) };
      await expect(cc.register(cred)).to.be.revertedWithCustomError(cc, "UnknownIssuer");
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
