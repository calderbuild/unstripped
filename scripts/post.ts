// Posts an image to the LabeledFeed example and prints what the registry and the feed say about it.
//
//   IMAGE=path/to/image.png npx hardhat run scripts/post.ts --network monadTestnet
//
// The file can be the original or a stripped copy: the hash is the same.
import { ethers, network } from "hardhat";
import { readFileSync } from "fs";
import { basename } from "path";
import { extract } from "../sdk/c2pa";
import { ABI } from "../sdk/registry";

const say = (s = "") => console.log(s);

async function main() {
  const dep = JSON.parse(readFileSync(`deployments/${network.name}.json`, "utf8"));
  const bytes = readFileSync(process.env.IMAGE!);
  let hash: string;
  try {
    hash = ethers.sha256(extract(bytes).stripped);
  } catch {
    hash = ethers.sha256(bytes); // no manifest: already a stripped copy
  }
  say(`image      ${basename(process.env.IMAGE!)}  (${bytes.length} bytes, no metadata: ${hash === ethers.sha256(bytes)})`);
  say(`sha256     ${hash}`);

  const cc = new ethers.Contract(dep.contentCredentials, ABI, ethers.provider);
  const r = await cc.provenanceOf(hash);
  say();
  say(`registry   ContentCredentials ${dep.contentCredentials}`);
  say(`  signer       ${r.signerOrg} / ${r.signerName}`);
  say(`  generator    ${r.generator}`);
  say(`  AI-generated ${r.aiGenerated}`);
  say(`  recorded     block ${r.registeredBlock} by ${r.registrant}`);
  const [log] = await cc.queryFilter(cc.filters.Registered(hash), Number(r.registeredBlock), Number(r.registeredBlock));
  if (log) say(`  register tx  ${log.transactionHash}`);

  const feed = await ethers.getContractAt("LabeledFeed", dep.labeledFeed);
  say();
  say(`feed       LabeledFeed ${dep.labeledFeed}`);
  say(`  post(${hash.slice(0, 10)}…, uri)`);
  const tx = await feed.post(hash, `ipfs://${basename(process.env.IMAGE!)}`);
  const rc = (await tx.wait())!;
  const ev = feed.interface.parseLog(rc.logs.find((l) => l.address.toLowerCase() === dep.labeledFeed.toLowerCase())!)!;
  say(`  tx           ${tx.hash}`);
  say(`  block        ${rc.blockNumber}, gas ${rc.gasUsed}`);
  say(`  Posted #${ev.args.id}: hasCredential=${ev.args.hasCredential} aiGenerated=${ev.args.aiGenerated}`);
}

main().catch((e) => (console.error(e), process.exit(1)));
