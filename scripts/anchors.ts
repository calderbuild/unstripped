// Writes sdk/anchors.json: the TBS of every official C2PA trust-list entry, so the relayer can find
// the anchor a manifest's top certificate chains to (manifests usually omit the root).
//
//   npx tsx scripts/anchors.ts
import { readFileSync, writeFileSync } from "fs";
import { splitCert } from "../sdk/c2pa";

const pems = [...readFileSync("fixtures/trust-list/C2PA-TRUST-LIST.pem", "utf8").matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)];
const tbs = pems.map((m) => "0x" + Buffer.from(splitCert(Buffer.from(m[1].replace(/\s+/g, ""), "base64")).tbs).toString("hex"));
writeFileSync("sdk/anchors.json", JSON.stringify(tbs) + "\n");
console.log(`${tbs.length} anchors -> sdk/anchors.json`);
