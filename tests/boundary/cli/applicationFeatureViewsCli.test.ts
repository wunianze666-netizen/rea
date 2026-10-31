import { writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { cliTest } from "../../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { applicationFeatureViewFixture } from "../../fixtures/applicationFeatureViews.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { inspectAnalysisView } from "../../../src/application/analysisView/AnalysisViewService.js";

cliTest(
  "queries an exact feature trace from an immutable portable bundle through the compiled CLI",
  async ({ cli }) => {
    const fixture = applicationFeatureViewFixture({ partial: true });
    const root = await createTestTempDirectory("rea-feature-view-cli-");
    const path = join(root, "bundle.json");
    const original = JSON.stringify(
      createEvidenceBundle([fixture.source, fixture.evidence]),
    );
    await writeFile(path, original);
    for (const view of [
      { kind: "summary" },
      {
        kind: "application-feature",
        collection: "nodes",
        fields: ["kind"],
        offset: 1,
        limit: 2,
      },
      {
        kind: "application-feature",
        collection: "edges",
        fields: ["relation"],
        limit: 2,
      },
    ]) {
      const request = {
        source: {
          kind: "retained-evidence",
          evidence_id: fixture.evidence.evidence_id,
        },
        view,
      };
      const result = await cli.run({
        arguments: [
          "inspect-analysis-view",
          JSON.stringify(request),
          "--evidence-bundle",
          path,
          "--json",
        ],
      });
      expect(result.exitCode, result.stderr).toBe(0);
      const evidence = parseEvidence(result.json);
      const expected = await inspectAnalysisView({
        source: { kind: "inline", evidence: fixture.evidence },
        view,
      });
      if (!expected.ok) throw expected.error;
      expect(evidence.evidence_id).toBe(expected.value.evidence_id);
      expect(evidence.normalized_result).toEqual(
        expected.value.normalized_result,
      );
      expect(evidence.evidence_links).toEqual([fixture.evidence.evidence_id]);
    }
    expect(await readFile(path, "utf8")).toBe(original);
  },
);
