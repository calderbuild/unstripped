import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";
import "dotenv/config";
import { HardhatUserConfig } from "hardhat/config";

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun", viaIR: true },
  },
  networks: {
    hardhat: { enableRip7212: true },
    monadTestnet: { url: "https://testnet-rpc.monad.xyz", chainId: 10143, accounts },
  },
};

export default config;
