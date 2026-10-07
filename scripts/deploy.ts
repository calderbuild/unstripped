// Deploys ContentCredentials to Monad testnet, adds the trust anchors, seals them, and registers
// the two fixture images so the registry has real entries from day one.
import { ethers, network } from "hardhat";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { extract } from "../sdk/c2pa";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`deployer ${deployer.address}, balance ${ethers.formatEther(await ethers.provider.getBalance(deployer))} MON`);
  const cc = await (await ethers.getContractFactory("ContentCredentials")).deploy();
  await cc.waitForDeployment();
  const address = await cc.getAddress();
  console.log(`ContentCredentials ${address}`);

  const openai = extract(readFileSync("fixtures/openai.png"));
  const gemini = extract(readFileSync("fixtures/gemini.png"));
  // SSL.com C2PA ICA R1 2025: issues OpenAI's signing certificates (RSA, verified on chain).
  await (await cc.addAnchor(openai.chain[1].tbs)).wait();
  // Google Media Processing Services: pinned signer. Its CA is P-384, which no EVM precompile verifies yet.
  await (await cc.addAnchor(gemini.chain[0].tbs)).wait();
  await (await cc.seal()).wait();
  console.log("anchors added and sealed");

  const regs: Record<string, string> = {};
  for (const [name, x, anchorTbs] of [["openai", openai, openai.chain[1].tbs], ["gemini", gemini, gemini.chain[0].tbs]] as const) {
    const tx = await cc.register({ ...x.credential, issuer: await cc.idOf(anchorTbs) });
    const rc = await tx.wait();
    regs[name] = tx.hash;
    console.log(`registered ${name} ${ethers.sha256(x.stripped)} gas ${rc!.gasUsed} tx ${tx.hash}`);
  }
  mkdirSync("deployments", { recursive: true });
  writeFileSync(
    `deployments/${network.name}.json`,
    JSON.stringify({ chainId: Number(network.config.chainId), contentCredentials: address, deployBlock: (await cc.deploymentTransaction()!.wait())!.blockNumber, fixtures: regs }, null, 2) + "\n",
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
