import tseslint from "typescript-eslint";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    ignores: ["dist/", "node_modules/"],
  },
  {
    files: ["**/*.ts"],
    extends: tseslint.configs.strictTypeChecked,
    languageOptions: {
      parserOptions: {
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
]);
