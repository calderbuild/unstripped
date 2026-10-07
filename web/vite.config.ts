import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The explorer imports the protocol's own SDK and deployment file from the repo root,
// so the check it re-runs in the browser is the same code the validators run.
export default defineConfig({
  plugins: [react()],
  resolve: { dedupe: ["ethers"] },
  server: { fs: { allow: [".."] } },
});
