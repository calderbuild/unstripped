// Deploys ContentCredentials to Monad testnet, anchors every entry of the official C2PA trust list
// that it can verify (29 of 30), seals the anchors, then adds the intermediate and signing
// certificates the fixtures need through the permissionless addIssuer path (each verified on chain
// against its parent), and registers the fixture images.
import { ethers, network } from "hardhat";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { extract, splitCert } from "../sdk/c2pa";
import { addIssuerArgs } from "../sdk/hints";

/// DER certificates from a PEM bundle.
const pem = (text: string) =>
  [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => Buffer.from(m[1].replace(/\s+/g, ""), "base64"));

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`deployer balance ${ethers.formatEther(await ethers.provider.getBalance(deployer))} MON`);
  const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
  await cc.waitForDeployment();
  const address = await cc.getAddress();
  const deployBlock = (await cc.deploymentTransaction()!.wait())!.blockNumber;
  console.log(`ContentCredentials ${address} (block ${deployBlock})`);

  const trustList = pem(readFileSync("fixtures/trust-list/C2PA-TRUST-LIST.pem", "utf8")).map((d) => splitCert(d).tbs);
  const anchored: string[] = [];
  for (const tbs of trustList) {
    const id = await cc.idOf(tbs).catch(() => null); // reverts for keys it cannot verify (P-521)
    if (!id) continue;
    await (await cc.addAnchor(tbs, { gasLimit: ((await cc.addAnchor.estimateGas(tbs)) * 11n) / 10n })).wait();
    anchored.push(id);
  }
  await (await cc.seal()).wait();
  console.log(`${anchored.length} of ${trustList.length} trust-list entries anchored, sealed`);
  const byName = (cn: string) => trustList.find((t) => Buffer.from(t).includes(Buffer.from(cn)))!;
  const roots = [byName("SSL.com C2PA RSA Root CA 2025"), byName("Trufo C2PA Root CA (2025"), byName("Google C2PA Root CA G3")];

  // Monad charges the gas limit, so size every limit to its estimate.
  const send = async (label: string, fn: any, ...args: unknown[]) => {
    const gasLimit = ((await fn.estimateGas(...args)) * 11n) / 10n;
    const tx = await fn(...args, { gasLimit });
    const rc = await tx.wait();
    console.log(`${label}: gas ${rc.gasUsed} tx ${tx.hash}`);
    return tx.hash as string;
  };
  const addIssuer = (label: string, cert: { tbs: Uint8Array; sig: Uint8Array }, parentTbs: Uint8Array) =>
    addIssuerArgs(cc, cert, parentTbs).then((args) => send(`addIssuer ${label}`, cc.addIssuer, ...args));

  const openai = extract(readFileSync("fixtures/openai.png"));
  const trufo = extract(readFileSync("fixtures/openai-trufo.png"));
  const gemini = extract(readFileSync("fixtures/gemini.png"));
  const txs: Record<string, string> = {};
  txs.sslcomIca = await addIssuer("SSL.com C2PA ICA R1 2025 (RSA)", openai.chain[1], roots[0]);
  txs.trufoIca = await addIssuer("Trufo C2PA Claim Signing CA (P-384)", trufo.chain[1], roots[1]);
  txs.openaiTrufoLeaf = await addIssuer("OpenAI Media Service via Trufo (P-384)", trufo.chain[0], trufo.chain[1].tbs);
  // Google's issuing CA is itself on the trust list, so it is already an anchor.
  txs.googleLeaf = await addIssuer("Google Media Processing Services (P-384)", gemini.chain[0], gemini.chain[1].tbs);

  for (const [name, x, issuerTbs] of [
    ["openai", openai, openai.chain[1].tbs],
    ["openai-trufo", trufo, trufo.chain[0].tbs],
    ["gemini", gemini, gemini.chain[0].tbs],
  ] as const) {
    txs[`register-${name}`] = await send(`register ${name} ${ethers.sha256(x.stripped)}`, cc.register, { ...x.credential, issuer: await cc.idOf(issuerTbs) });
  }

  mkdirSync("deployments", { recursive: true });
  writeFileSync(
    `deployments/${network.name}.json`,
    JSON.stringify({ chainId: Number(network.config.chainId), contentCredentials: address, deployBlock, trustListAnchors: anchored.length, txs }, null, 2) + "\n",
  );
  console.log(`deployer balance ${ethers.formatEther(await ethers.provider.getBalance(deployer))} MON`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
