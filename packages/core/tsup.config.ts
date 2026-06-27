import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/x402/index.ts",
    "src/adapters/cdp.ts",
    "src/adapters/viem.ts",
  ],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "node22",
  // viem / sdk deps stay external
  skipNodeModulesBundle: true,
});
