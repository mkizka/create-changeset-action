import { configs } from "@mkizka/eslint-config";

export default [
  {
    ignores: ["dist/**"],
  },
  ...configs.typescript(),
];
