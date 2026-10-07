// Relayer: submits a credential to the registry so people can register without a wallet.
// It cannot be used to plant false records: the contract verifies every signature itself, and
// the relayer simulates the call first so invalid credentials never cost gas.
import { JsonRpcProvider, Wallet, isHexString } from "ethers";
import { registry } from "../sdk/registry";
import deployment from "../deployments/monadTestnet.json";

const FIELDS = ["issuer", "leafTbs", "leafSig", "protectedHeader", "claim", "signature", "hashAssertion", "actionsAssertion"];
const MAX_BYTES = 64 * 1024;

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST a credential" });
  const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  const cred = body?.credential;
  if (!cred || !FIELDS.every((f) => typeof cred[f] === "string" && isHexString(cred[f]))) {
    return res.status(400).json({ error: `credential needs hex fields: ${FIELDS.join(", ")}` });
  }
  if (FIELDS.reduce((n, f) => n + cred[f].length / 2, 0) > MAX_BYTES) return res.status(413).json({ error: "credential too large" });

  const key = process.env.RELAYER_KEY;
  if (!key) return res.status(500).json({ error: "relayer not configured" });
  const provider = new JsonRpcProvider(process.env.MONAD_RPC ?? "https://testnet-rpc.monad.xyz", deployment.chainId, { staticNetwork: true });
  const c = registry(deployment.contentCredentials, new Wallet(key, provider));
  try {
    const assetHash: string = await c.register.staticCall(cred);
    if (await c.isRegistered(assetHash)) return res.status(200).json({ assetHash, already: true });
    // Monad charges the gas limit, not gas used, so size it to the estimate.
    const gasLimit = ((await c.register.estimateGas(cred)) * 12n) / 10n;
    const tx = await c.register(cred, { gasLimit });
    const rc = await tx.wait();
    return res.status(200).json({ assetHash, txHash: tx.hash, block: rc?.blockNumber, gasUsed: rc?.gasUsed.toString() });
  } catch (e: any) {
    const reason = e?.revert?.name ?? e?.shortMessage ?? String(e).slice(0, 160);
    return res.status(422).json({ error: `the registry rejected this credential: ${reason}` });
  }
}
