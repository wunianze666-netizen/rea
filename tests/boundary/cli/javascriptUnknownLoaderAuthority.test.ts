import { createHash } from "node:crypto";
import { expect } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { analyzeJavaScriptDirectory } from "../../support/cli/javascriptApplication.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const source = `const box = {load: module.require};
box.load = box.load || null;
box.load.call(module, "./dep.cjs");
function known(target) { return require(target); }
`;
const digest = createHash("sha256").update(source).digest("hex");

for (const surface of ["CLI", "stdio MCP"] as const) {
  cliTest(
    `retains unknown loader identity without a literal through ${surface}`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-loader-authority-");
      await writeFixtureFiles(root, {
        "package.json":
          '{"name":"loader-proof-fixture","type":"commonjs","main":"main.cjs"}\n',
        "main.cjs": source,
      });
      const result = await analyzeJavaScriptDirectory(surface, cli, root, {
        sourcePaths: ["package.json", "main.cjs"],
      });
      const candidate = result.graph.edges.find(
        ({ properties }) =>
          properties.expression === 'box.load.call(module, "./dep.cjs")',
      );
      const known = result.graph.edges.find(
        ({ properties }) => properties.expression === "require(target)",
      );
      expect(candidate).toMatchObject({
        properties: {
          kind: "require",
          specifier: null,
          loader_authority: "candidate",
          resolution_mode: null,
          resolved_path: null,
        },
        evidence: {
          confidence: "low",
          artifact: { sha256: digest },
          location: { value: { source: "main.cjs", start: { line: 3 } } },
        },
      });
      expect(candidate?.evidence.limitations).toContain(
        "The module loader is unknown, so this dependency cannot be resolved against the source file.",
      );
      expect(known).toMatchObject({
        properties: {
          kind: "require",
          specifier: null,
          resolution_mode: "require",
        },
        evidence: { confidence: "high", artifact: { sha256: digest } },
      });
      expect(known?.properties).not.toHaveProperty("loader_authority");
    },
  );
}
