// Relayer: submits a credential to the registry so people can register without a wallet.
// It cannot be used to plant false records: the contract verifies every signature itself, and
// the relayer simulates the call first so invalid credentials never cost gas.
import { JsonRpcProvider, Wallet, isHexString } from "ethers";
import { registry } from "../sdk/registry";
import { addIssuerArgs } from "../sdk/hints";
import deployment from "../deployments/monadTestnet.json";

// Monad charges the gas limit, not gas used, so size each limit to its estimate.
const sized = async (fn: any, ...args: unknown[]) => fn(...args, { gasLimit: ((await fn.estimateGas(...args)) * 12n) / 10n });

/// A signer the registry has not seen yet (a rotated OpenAI or Google certificate, say) is added
/// first, verified on chain against its CA. Walks the chain from the top so each certificate's
/// parent is known by the time it is added. Returns the labels of what it added.
export async function onboard(c: any, chain: { tbs: string; sig: string }[]): Promise<string[]> {
  const added: string[] = [];
  const known = async (tbs: string) => {
    const id = await c.idOf(tbs).catch(() => null);
    return id && Number((await c.issuers(id)).keyType) !== 0;
  };
  for (let i = chain.length - 2; i >= 0; i--) {
    if (await known(chain[i].tbs)) continue;
    if (!(await known(chain[i + 1].tbs))) continue;
    const cert = { tbs: Buffer.from(chain[i].tbs.slice(2), "hex"), sig: Buffer.from(chain[i].sig.slice(2), "hex") };
    const rc = await (await sized(c.addIssuer, ...(await addIssuerArgs(c, cert, Buffer.from(chain[i + 1].tbs.slice(2), "hex"))))).wait();
    added.push(rc.hash);
  }
  return added;
}

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
    const chain = Array.isArray(body.chain) ? body.chain.slice(0, 4) : [];
    const onboarded = chain.every((x: any) => isHexString(x?.tbs) && isHexString(x?.sig)) ? await onboard(c, chain) : [];
    if (onboarded.length && cred.issuer === "0x" + "00".repeat(32)) cred.issuer = await c.idOf(chain[0].tbs);
    const assetHash: string = await c.register.staticCall(cred);
    if (await c.isRegistered(assetHash)) return res.status(200).json({ assetHash, already: true });
    const tx = await sized(c.register, cred);
    const rc = await tx.wait();
    return res.status(200).json({ assetHash, txHash: tx.hash, block: rc?.blockNumber, gasUsed: rc?.gasUsed.toString(), onboarded });
  } catch (e: any) {
    const reason = e?.revert?.name ?? e?.shortMessage ?? String(e).slice(0, 160);
    return res.status(422).json({ error: `the registry rejected this credential: ${reason}` });
  }
}
