import { builtinModules } from "node:module";

import { defineConfig } from "vite";

const external = [...builtinModules, ...builtinModules.map((m) => `node:${m}`)];

export default defineConfig({
  build: {
    target: "esnext",
    minify: false,
    sourcemap: true,
    lib: {
      entry: "src/index.ts",
      fileName: "index",
      formats: ["es"],
    },
    rollupOptions: {
      external,
    },
  },
});
