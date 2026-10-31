import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { z } from "zod";
import { inspectAnalysisViewInputSchema } from "../../../src/domain/analysisView/analysisView.js";
import type { Evidence } from "../../../src/domain/evidence.js";
import { expect, it, onTestFinished, vi } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { applicationFeatureViewFixture } from "../../fixtures/applicationFeatureViews.js";
import { createMcpSchemaValidation } from "../../fixtures/mcpSchemaValidation.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { analysisViewResultSchema } from "../../../src/domain/analysisView/analysisView.js";
import { applicationFeatureTraceResultSchema } from "../../../src/domain/javascript/javascriptFeatureTraceSchemas.js";
import * as workflows from "../../../src/application/javascript/JavaScriptApplicationWorkflowService.js";

const connect = async (profile: "full" | "compact", source: Evidence) => {
  let providerStarts = 0;
  const session = createTestBinarySession(() => {
    providerStarts++;
    throw new Error("Views must not start a provider");
  });
  const recorded = session.recordEvidence(source);
  if (!recorded.ok) throw recorded.error;
  const server = createServer(
    { kind: "session", session },
    {
      environment: {
        ...process.env,
        REA_MCP_INPUT_SCHEMA_PROFILE: profile,
        REA_MCP_OUTPUT_SCHEMA_PROFILE: "full",
      },
    },
  );
  const validation = createMcpSchemaValidation();
  const client = new Client(
    { name: "feature-views", version: "1" },
    { jsonSchemaValidator: validation },
  );
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
    validation.clear();
  });
  const [local, remote] = InMemoryTransport.createLinkedPair();
  await server.connect(remote);
  await client.connect(local);
  const { tools } = await client.listTools();
  const call = async (
    name: string,
    arguments_: Record<string, unknown>,
    validInput = true,
  ) => {
    const definition = tools.find((tool) => tool.name === name);
    if (definition === undefined) throw new Error(`Missing ${name}`);
    if (validInput)
      expect(
        validation.assertions.validate(definition.inputSchema, arguments_),
        JSON.stringify(validation.assertions.errors),
      ).toBe(true);
    return client.callTool(
      { name, arguments: arguments_ },
      { toolDefinition: definition },
    );
  };
  return { call, session, providerStarts: () => providerStarts };
};

it.each(["full", "compact"] as const)(
  "recovers an oversized retained feature trace through registered %s MCP views",
  async (profile) => {
    const fixture = applicationFeatureViewFixture({
      payloadBytes: 11 * 1024 * 1024,
      partial: true,
    });
    const producer = vi.spyOn(workflows, "traceApplicationFeatureEvidence");
    onTestFinished(() => {
      producer.mockRestore();
    });
    const { call, session, providerStarts } = await connect(
      profile,
      fixture.source,
    );
    const full = await call("trace_application_feature", {
      application: {
        kind: "retained-evidence",
        evidence_id: fixture.source.evidence_id,
      },
      seed: { kind: "channel", value: "project:open", match: "exact" },
      direction: "both",
    });
    expect(full.isError).toBe(true);
    expect(parseMcpToolError(full).error.code).toBe("resource_constraint");
    const retained = session
      .exportEvidenceBundle()
      .records.filter(
        (record) => record.operation === "trace_application_feature",
      );
    expect(retained).toHaveLength(1);
    const parent = retained[0];
    if (parent === undefined)
      throw new Error("Completed trace was not retained");
    const recovery = z
      .object({
        evidence_reference: z.object({
          kind: z.literal("retained-evidence"),
          evidence_id: z.string(),
        }),
        continuation: z.object({
          name: z.literal("inspect_analysis_view"),
          arguments: inspectAnalysisViewInputSchema,
        }),
      })
      .parse(parseMcpToolError(full).error.details?.reported_limits);
    expect(recovery.evidence_reference.evidence_id).toBe(parent.evidence_id);
    expect(recovery.continuation.arguments).toMatchObject({
      source: recovery.evidence_reference,
      view: { kind: "summary" },
    });
    const report = applicationFeatureTraceResultSchema.parse(
      parent.normalized_result,
    );
    expect(
      report.graph?.nodes.some((node) =>
        node.observations.some(
          (observation) =>
            typeof observation.properties.view_fixture_payload === "string",
        ),
      ),
    ).toBe(true);
    const requestView = async (input: Record<string, unknown>) => {
      const response = await call("inspect_analysis_view", input);
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      expect(Buffer.byteLength(JSON.stringify(response))).toBeLessThan(
        64 * 1024,
      );
      const evidence = parseEvidence(response.structuredContent);
      expect(evidence.evidence_links).toContain(parent.evidence_id);
      return analysisViewResultSchema.parse(evidence.normalized_result);
    };
    const select = (view: Record<string, unknown>) =>
      requestView({ source: recovery.evidence_reference, view });
    const summary = await requestView(recovery.continuation.arguments);
    expect(summary).toMatchObject({
      parent_operation: "trace_application_feature",
      summary: {
        trace_id: report.trace_id,
        source_coverage: { status: "partial" },
      },
    });
    const nodeIds: string[] = [];
    for (
      let offset = 0;
      offset < (report.graph?.nodes.length ?? 0);
      offset += 2
    ) {
      const page = await select({
        kind: "application-feature",
        collection: "nodes",
        fields: ["kind"],
        offset,
        limit: 2,
      });
      if (page.kind !== "application-feature")
        throw new Error("Expected feature page");
      for (const row of page.items) {
        if (!("node_id" in row)) throw new Error("Expected node identity");
        nodeIds.push(row.node_id);
      }
      expect(page.source_coverage.status).toBe("partial");
      expect(JSON.stringify(page.items)).not.toContain("view_fixture_payload");
    }
    expect(nodeIds).toEqual(report.graph?.nodes.map((node) => node.node_id));
    const edges = await select({
      kind: "application-feature",
      collection: "edges",
      limit: 100,
    });
    expect(edges).toMatchObject({
      coverage: { total: report.graph?.edges.length, exhausted: true },
    });
    expect(producer).toHaveBeenCalledTimes(1);
    const invalid = await call(
      "inspect_analysis_view",
      {
        source: recovery.evidence_reference,
        view: {
          kind: "application-feature",
          collection: "edges",
          fields: ["observations"],
        },
      },
      false,
    );
    expect(parseMcpToolError(invalid).error.code).toBe("invalid_request");
    expect(providerStarts()).toBe(0);
    expect(session.evidenceById(parent.evidence_id)?.evidence_id).toBe(
      parent.evidence_id,
    );
  },
  60_000,
);
