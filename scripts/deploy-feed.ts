// Deploys the LabeledFeed example against the live registry and posts the stripped OpenAI sample.
import { ethers, network } from "hardhat";
import { readFileSync, writeFileSync } from "fs";
import { extract } from "../sdk/c2pa";

async function main() {
  const file = `deployments/${network.name}.json`;
  const dep = JSON.parse(readFileSync(file, "utf8"));
  const feed = await (await ethers.getContractFactory("LabeledFeed")).deploy(dep.contentCredentials);
  await feed.waitForDeployment();
  const hash = ethers.sha256(extract(readFileSync("fixtures/openai.png")).stripped);
  const tx = await feed.post(hash, "https://unstripped.vercel.app/samples/openai-stripped.png");
  await tx.wait();
  const p = await feed.posts(0);
  console.log(`LabeledFeed ${await feed.getAddress()} post 0: hasCredential=${p.hasCredential} aiGenerated=${p.aiGenerated} tx ${tx.hash}`);
  writeFileSync(file, JSON.stringify({ ...dep, labeledFeed: await feed.getAddress(), txs: { ...dep.txs, feedPost: tx.hash } }, null, 2) + "\n");
}
main().catch((e) => (console.error(e), process.exit(1)));
