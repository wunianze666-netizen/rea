import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import {
  createEvidenceBundle,
  evidenceBundleSchema,
} from "../../../src/domain/evidenceBundle.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { functionComparisonResultSchema } from "../../../src/domain/functionComparisonSchemas.js";
import { functionSelfComparisonFixture } from "../../fixtures/functionSelfComparison.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";

const connect = async (
  profile: "full" | "compact",
  sourceId: string,
  onEngineStart: () => void,
) => {
  const session = createTestBinarySession(() => {
    onEngineStart();
    throw new Error("Retained comparison must not start a provider");
  });
  const harness = await createApplicationMcpHarness({
    session,
    serverOptions: {
      environment: { REA_MCP_OUTPUT_SCHEMA_PROFILE: profile },
    },
  });
  const { tools } = await harness.client.listTools();
  const call = (name: string, arguments_: Record<string, unknown>) => {
    const toolDefinition = tools.find((tool) => tool.name === name);
    if (toolDefinition === undefined) throw new Error(`Missing ${name}`);
    return harness.client.callTool(
      { name, arguments: arguments_ },
      { toolDefinition },
    );
  };
  const advertised = await advertisedMcpToolSchemas(
    harness.client,
    "compare_functions",
  );
  const compare = async (rightId = sourceId) => {
    const response = await harness.client.callTool(
      {
        name: "compare_functions",
        arguments: {
          left: {
            kind: "retained-evidence",
            evidence_id: sourceId,
          },
          right: { kind: "retained-evidence", evidence_id: rightId },
        },
      },
      { toolDefinition: advertised.toolDefinition },
    );
    expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
    expect(
      advertised.ajv.validate(
        advertised.outputSchema,
        response.structuredContent,
      ),
      JSON.stringify(advertised.ajv.errors),
    ).toBe(true);
    const evidence = parseEvidence(response.structuredContent);
    return {
      evidence,
      result: functionComparisonResultSchema.parse(evidence.normalized_result),
    };
  };
  return { ...harness, call, compare };
};

it.each(["full", "compact"] as const)(
  "same retained observation remains explicit through comparison and offline replay (%s)",
  async (profile) => {
    const root = await createTestTempDirectory("rea-function-self-mcp-");
    const source = functionSelfComparisonFixture();
    const other = functionSelfComparisonFixture("another-selection");
    const inputPath = join(root, "sources.json");
    await writeFile(
      inputPath,
      JSON.stringify(createEvidenceBundle([source, other])),
    );
    const inputBytes = await readFile(inputPath);
    let engineStarts = 0;
    const first = await connect(profile, source.evidence_id, () => {
      engineStarts++;
    });
    expect(
      (await first.call("import_evidence_bundle", { path: inputPath })).isError,
    ).not.toBe(true);
    const self = await first.compare();
    expect(self.result.function_match).toMatchObject({
      status: "matched",
      method: "same-evidence",
      evidence_id: source.evidence_id,
    });
    expect(
      self.result.dimensions.find(({ dimension }) => dimension === "identity"),
    ).toMatchObject({ status: "unchanged" });
    expect(
      self.result.dimensions.find(({ dimension }) => dimension === "calls"),
    ).toMatchObject({ status: "unknown" });
    expect(self.result.status).toBe("unknown");
    expect(
      self.result.dimensions.every(
        ({ evidence_links }) =>
          evidence_links[0] === source.evidence_id &&
          evidence_links[1] === source.evidence_id,
      ),
    ).toBe(true);
    const behavior = await first.call("find_changed_behavior", {
      comparisons: [
        {
          kind: "retained-evidence",
          evidence_id: self.evidence.evidence_id,
        },
      ],
    });
    expect(behavior.isError, JSON.stringify(behavior.content)).not.toBe(true);
    expect(
      parseEvidence(behavior.structuredContent).normalized_result,
    ).toMatchObject({ behavior_status: "unknown" });
    const different = await first.compare(other.evidence_id);
    expect(different.result.function_match).toMatchObject({
      status: "ambiguous",
      method: "explicit",
    });
    const output = join(root, "exported.json");
    expect(
      (await first.call("export_evidence_bundle", { path: output })).isError,
    ).not.toBe(true);
    const bytes = await readFile(output);
    const bundle = evidenceBundleSchema.parse(
      JSON.parse(bytes.toString("utf8")),
    );
    expect(
      bundle.records.filter(
        (record) => record.evidence_id === source.evidence_id,
      ),
    ).toEqual([source]);
    const offline = await connect(profile, source.evidence_id, () => {
      engineStarts++;
    });
    expect(
      (await offline.call("import_evidence_bundle", { path: output })).isError,
    ).not.toBe(true);
    const replay = await offline.compare();
    expect(replay.evidence.evidence_id).toBe(self.evidence.evidence_id);
    expect(replay.result).toEqual(self.result);
    expect((await readFile(inputPath)).equals(inputBytes)).toBe(true);
    expect((await readFile(output)).equals(bytes)).toBe(true);
    expect(engineStarts).toBe(0);
  },
);
