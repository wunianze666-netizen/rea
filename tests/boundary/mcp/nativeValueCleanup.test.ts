import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { Ajv2020 } from "ajv/dist/2020.js";
import { analysisErrorJsonSchema } from "../../../src/contracts/errorSchemas.js";
import { evidenceBundleSchema } from "../../../src/domain/evidenceBundle.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { nativeValueTraceSchema } from "../../../src/domain/native/nativeValueTrace.js";
import { nativeValueCleanupFixture } from "../../fixtures/nativeValueCleanup.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createSessionMcpHarness } from "./sessionMcpHarness.js";

const resources: Array<{ close(): Promise<unknown> }> = [];
const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
  for (const resource of resources.splice(0)) await resource.close();
});
const validateError = new Ajv2020({
  strict: false,
  validateFormats: false,
}).compile(analysisErrorJsonSchema);
const phases = ["seed", "resolve", "callee"] as const;
const cases = phases.flatMap((phase) =>
  (["full", "compact"] as const).map((profile) => ({ phase, profile })),
);

it.each(cases)(
  "native values keep $phase cleanup typed through the advertised $profile contract",
  async ({ phase, profile }) => {
    const fixture = nativeValueCleanupFixture({ phase });
    const root = await createTestTempDirectory("rea-native-cleanup-mcp-");
    const harness = await createSessionMcpHarness(
      root,
      fixture.provider,
      resources,
      undefined,
      profile,
    );
    const { tools } = await harness.mcp.listTools();
    const call = (name: string, arguments_: Record<string, unknown> = {}) => {
      const toolDefinition = tools.find((tool) => tool.name === name);
      if (toolDefinition === undefined) throw new Error(`Missing ${name}`);
      return harness.mcp.callTool(
        { name, arguments: arguments_ },
        { toolDefinition },
      );
    };
    cleanup.push(async () => {
      fixture.proveCleanup();
      await call("close_binary");
    });
    expect(
      (await call("open_binary", { path: harness.first })).isError,
    ).not.toBe(true);
    const advertised = await advertisedMcpToolSchemas(
      harness.mcp,
      "trace_native_values",
    );
    const response = await harness.mcp.callTool(
      {
        name: "trace_native_values",
        arguments: { procedure: "0x1000", max_depth: 1 },
      },
      { toolDefinition: advertised.toolDefinition },
    );
    expect(response.isError).toBe(true);
    expect(response.structuredContent).toBeUndefined();
    const failure = parseMcpToolError(response).error;
    expect(validateError(failure), JSON.stringify(validateError.errors)).toBe(
      true,
    );
    expect(failure).toMatchObject({
      code: "cleanup_incomplete",
      retryable: false,
      details: { resources: ["owned native fixture worker"] },
    });
    expect(fixture.calls).not.toContain("analyze_function:0x4000");
    if (phase === "resolve")
      expect(fixture.calls).not.toContain("resolve_native_call_targets:0x1008");
    if (phase !== "seed") {
      const partial = fixture.partial();
      expect(partial).toBeDefined();
      if (partial === undefined)
        throw new Error("Expected completed seed Evidence");
      expect(failure).toMatchObject({
        details: { partial_observation: { evidence_id: partial.evidence_id } },
      });
      const path = join(root, "admitted.json");
      expect((await call("export_evidence_bundle", { path })).isError).not.toBe(
        true,
      );
      const bundle = evidenceBundleSchema.parse(
        JSON.parse(await readFile(path, "utf8")),
      );
      expect(
        bundle.records.find(
          (record) =>
            record.operation === "analyze_function" &&
            record.parameters.procedure === "0x1000",
        )?.normalized_result,
      ).toEqual(partial.normalized_result);
      expect(
        bundle.records.some(
          (record) => record.operation === "trace_native_values",
        ),
      ).toBe(false);
      if (phase === "callee") {
        expect(
          bundle.records.filter(
            (record) => record.operation === "analyze_function",
          ),
        ).toHaveLength(2);
        expect(
          bundle.records.find(
            (record) =>
              record.operation === "analyze_function" &&
              record.parameters.procedure === "0x2000",
          ),
        ).toBeDefined();
      }
    }
    const firstClose = await call("close_binary");
    expect(firstClose.isError).toBe(true);
    const closed = parseMcpToolError(firstClose).error;
    expect(validateError(closed), JSON.stringify(validateError.errors)).toBe(
      true,
    );
    expect(closed).toMatchObject({
      code: "cleanup_incomplete",
      recovery: { kind: "retry_cleanup", operation: "close_binary" },
    });
    const calls = [...fixture.calls];
    fixture.proveCleanup();
    expect((await call("close_binary")).isError).not.toBe(true);
    expect(fixture.failure()?.cleanupIncomplete).toBe(false);
    expect(fixture.calls).toEqual(calls);
    expect(failure.code).toBe("cleanup_incomplete");
  },
);

it.each(["resolve", "callee"] as const)(
  "ordinary %s failures still yield a partial native value trace",
  async (phase) => {
    const fixture = nativeValueCleanupFixture({ phase, state: "plain" });
    const root = await createTestTempDirectory("rea-native-ordinary-mcp-");
    const harness = await createSessionMcpHarness(
      root,
      fixture.provider,
      resources,
      undefined,
      "compact",
    );
    const { tools } = await harness.mcp.listTools();
    const open = tools.find((tool) => tool.name === "open_binary");
    const close = tools.find((tool) => tool.name === "close_binary");
    if (open === undefined || close === undefined)
      throw new Error("Missing session tools");
    cleanup.push(() =>
      harness.mcp.callTool(
        { name: "close_binary", arguments: {} },
        { toolDefinition: close },
      ),
    );
    expect(
      (
        await harness.mcp.callTool(
          { name: "open_binary", arguments: { path: harness.first } },
          { toolDefinition: open },
        )
      ).isError,
    ).not.toBe(true);
    const { toolDefinition, ajv, outputSchema } =
      await advertisedMcpToolSchemas(harness.mcp, "trace_native_values");
    const response = await harness.mcp.callTool(
      {
        name: "trace_native_values",
        arguments: { procedure: "0x1000", max_depth: 1 },
      },
      { toolDefinition },
    );
    expect(response.isError).not.toBe(true);
    expect(
      ajv.validate(outputSchema, response.structuredContent),
      JSON.stringify(ajv.errors),
    ).toBe(true);
    expect(
      nativeValueTraceSchema.parse(
        parseEvidence(response.structuredContent).normalized_result,
      ).unknowns,
    ).toContainEqual(
      expect.objectContaining({ reason: fixture.failure()?.message }),
    );
    expect(fixture.calls).toContain("analyze_function:0x4000");
  },
);
