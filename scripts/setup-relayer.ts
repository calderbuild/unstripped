// Creates the relayer wallet once (key in ~/.secrets/unstripped-relayer.env) and tops it up.
import { Wallet, JsonRpcProvider, parseEther, formatEther } from "ethers";
import { existsSync, readFileSync, writeFileSync } from "fs";
import "dotenv/config";

async function main() {
  const file = `${process.env.HOME}/.secrets/unstripped-relayer.env`;
  if (!existsSync(file)) {
    const w = Wallet.createRandom();
    writeFileSync(file, `RELAYER_KEY=${w.privateKey}\nRELAYER_ADDRESS=${w.address}\n`, { mode: 0o600 });
  }
  const address = readFileSync(file, "utf8").match(/RELAYER_ADDRESS=(\S+)/)![1];
  const p = new JsonRpcProvider("https://testnet-rpc.monad.xyz", 10143, { staticNetwork: true });
  const d = new Wallet(process.env.PRIVATE_KEY!, p);
  if ((await p.getBalance(address)) < parseEther("3")) await (await d.sendTransaction({ to: address, value: parseEther("3") - (await p.getBalance(address)) })).wait();
  console.log(`relayer ${address} balance ${formatEther(await p.getBalance(address))} MON`);
}
main().catch((e) => (console.error(e), process.exit(1)));
