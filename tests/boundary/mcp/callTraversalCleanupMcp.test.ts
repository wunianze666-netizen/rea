import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { Ajv2020 } from "ajv/dist/2020.js";
import { analysisErrorJsonSchema } from "../../../src/contracts/errorSchemas.js";
import { evidenceBundleSchema } from "../../../src/domain/evidenceBundle.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { callTraversalCleanupFixture } from "../../fixtures/callTraversalCleanup.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createSessionMcpHarness } from "./sessionMcpHarness.js";

const resources: Array<{ close(): Promise<unknown> }> = [];
const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
  for (const resource of resources.splice(0)) await resource.close();
});
const validateError = new Ajv2020({
  strict: false,
  validateFormats: false,
}).compile(analysisErrorJsonSchema);
const tools = ["get_call_graph", "trace_call_path"] as const;
const cases = tools.flatMap((tool) =>
  (["full", "compact"] as const).map((profile) => ({ tool, profile })),
);

it.each(cases)(
  "$tool stops on cleanup failure through the advertised $profile MCP contract",
  async ({ tool, profile }) => {
    const direction = profile === "full" ? "forward" : "backward";
    const operation =
      direction === "forward" ? "procedure_callees" : "procedure_callers";
    const fixture = callTraversalCleanupFixture(direction);
    const root = await createTestTempDirectory("rea-graph-cleanup-mcp-");
    const harness = await createSessionMcpHarness(
      root,
      fixture.provider,
      resources,
      undefined,
      profile,
    );
    const { tools: definitions } = await harness.mcp.listTools();
    const call = (name: string, arguments_: Record<string, unknown> = {}) => {
      const toolDefinition = definitions.find(
        (definition) => definition.name === name,
      );
      if (toolDefinition === undefined) throw new Error(`Missing ${name}`);
      return harness.mcp.callTool(
        { name, arguments: arguments_ },
        { toolDefinition },
      );
    };
    cleanups.push(async () => {
      fixture.proveCleanup();
      await call("close_binary");
    });
    expect(
      (await call("open_binary", { path: harness.first })).isError,
    ).not.toBe(true);
    const advertised = await advertisedMcpToolSchemas(harness.mcp, tool);
    const response = await harness.mcp.callTool(
      {
        name: tool,
        arguments:
          tool === "get_call_graph"
            ? { address: "0x1", direction }
            : { start: "0x1", goal: "0x4", direction },
      },
      { toolDefinition: advertised.toolDefinition },
    );
    expect(response.isError).toBe(true);
    expect(response.structuredContent).toBeUndefined();
    const failure = parseMcpToolError(response).error;
    const partial = fixture.partial();
    expect(partial).toBeDefined();
    if (partial === undefined)
      throw new Error("Expected the producer's retained partial observation");
    expect(validateError(failure), JSON.stringify(validateError.errors)).toBe(
      true,
    );
    expect(failure).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        operation,
        resources: ["owned synthetic relationship worker"],
        partial_observation: { evidence_id: partial.evidence_id },
      },
    });
    expect(fixture.reads).toEqual(["0x1", "0x2"]);
    expect(failure.retryable).toBe(false);
    const bundlePath = join(root, "admitted.json");
    expect(
      (await call("export_evidence_bundle", { path: bundlePath })).isError,
    ).not.toBe(true);
    const bundle = evidenceBundleSchema.parse(
      JSON.parse(await readFile(bundlePath, "utf8")),
    );
    expect(
      bundle.records.find(
        (record) =>
          record.operation === operation &&
          record.parameters.procedure === "0x1",
      )?.normalized_result,
    ).toEqual(["0x2", "0x3"]);
    expect(bundle.records.some((record) => record.operation === tool)).toBe(
      false,
    );
    const closed = await call("close_binary");
    expect(closed.isError).toBe(true);
    const pending = parseMcpToolError(closed).error;
    expect(validateError(pending), JSON.stringify(validateError.errors)).toBe(
      true,
    );
    expect(pending).toMatchObject({
      code: "cleanup_incomplete",
      recovery: { kind: "retry_cleanup", operation: "close_binary" },
    });
    fixture.proveCleanup();
    expect((await call("close_binary")).isError).not.toBe(true);
    expect(fixture.failure()?.cleanupIncomplete).toBe(false);
    expect(fixture.failure()?.cleanupRetry).toBeUndefined();
    expect(fixture.reads).toEqual(["0x1", "0x2"]);
    expect(failure.code).toBe("cleanup_incomplete");
  },
);

it.each(tools)(
  "$tool preserves ordinary read failures as successful partial results",
  async (tool) => {
    const fixture = callTraversalCleanupFixture("forward", false);
    const root = await createTestTempDirectory("rea-graph-ordinary-mcp-");
    const harness = await createSessionMcpHarness(
      root,
      fixture.provider,
      resources,
      undefined,
      "compact",
    );
    const { tools: definitions } = await harness.mcp.listTools();
    const opened = definitions.find(
      (definition) => definition.name === "open_binary",
    );
    if (opened === undefined) throw new Error("Missing open_binary");
    const close = definitions.find(
      (definition) => definition.name === "close_binary",
    );
    if (close === undefined) throw new Error("Missing close_binary");
    cleanups.push(() =>
      harness.mcp.callTool(
        { name: "close_binary", arguments: {} },
        { toolDefinition: close },
      ),
    );
    expect(
      (
        await harness.mcp.callTool(
          { name: "open_binary", arguments: { path: harness.first } },
          { toolDefinition: opened },
        )
      ).isError,
    ).not.toBe(true);
    const { toolDefinition, ajv, outputSchema } =
      await advertisedMcpToolSchemas(harness.mcp, tool);
    const response = await harness.mcp.callTool(
      {
        name: tool,
        arguments:
          tool === "get_call_graph"
            ? { address: "0x1" }
            : { start: "0x1", goal: "0x4" },
      },
      { toolDefinition },
    );
    expect(response.isError).not.toBe(true);
    expect(
      ajv.validate(outputSchema, response.structuredContent),
      JSON.stringify(ajv.errors),
    ).toBe(true);
    expect(fixture.reads).toContain("0x3");
    if (tool === "trace_call_path")
      expect(
        parseEvidence(response.structuredContent).normalized_result,
      ).toMatchObject({ goal_status: "reached" });
  },
);
