// Adds the signing chain of an image to the registry ahead of time, so the first person who
// registers an image from that signer does not pay for (or wait on) the certificate checks.
//
//   IMAGE=fixtures/openai-trufo.png npx hardhat run scripts/onboard.ts --network monadTestnet
import { ethers, network } from "hardhat";
import { readFileSync } from "fs";
import { extract } from "../sdk/c2pa";
import { registry } from "../sdk/registry";
import { onboard } from "../api/register";

async function main() {
  const dep = JSON.parse(readFileSync(`deployments/${network.name}.json`, "utf8"));
  const key = readFileSync(`${process.env.HOME}/.secrets/unstripped-relayer.env`, "utf8").match(/RELAYER_KEY=(\S+)/)![1];
  const c = registry(dep.contentCredentials, new ethers.Wallet(key, ethers.provider));
  const hex = (b: Uint8Array) => ethers.hexlify(b);
  const chain = extract(readFileSync(process.env.IMAGE!)).chain.map((x) => ({ tbs: hex(x.tbs), sig: hex(x.sig) }));
  const added = await onboard(c, chain);
  console.log(added.length ? `added ${added.length}: ${added.join(" ")}` : "chain already known");
}

main().catch((e) => (console.error(e), process.exit(1)));
