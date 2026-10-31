import { expect, it } from "vitest";
import { applicationFeatureViewFixture } from "../../../tests/fixtures/applicationFeatureViews.js";
import { createApplicationFeatureTraceEvidence } from "../javascript/JavaScriptApplicationWorkflowEvidence.js";
import {
  inspectAnalysisViewInputSchema,
  analysisViewResultSchema,
} from "../../domain/analysisView/analysisView.js";
import { inspectAnalysisView } from "./AnalysisViewService.js";
import { traceApplicationFeatureEvidence } from "../javascript/JavaScriptApplicationWorkflowService.js";
import {
  analysisViewJavaScriptAnalysis,
  analysisViewJavaScriptEvidence,
} from "../../../tests/fixtures/analysisView.js";

it("summarizes completed feature-trace Evidence without repeating its graph", async () => {
  const application = analysisViewJavaScriptAnalysis();
  const node = application.graph.nodes[0];
  if (node === undefined) throw new Error("Expected fixture graph");
  const trace = traceApplicationFeatureEvidence({
    application: analysisViewJavaScriptEvidence(application),
    seed: { kind: "node-id", value: node.node_id },
    direction: "both",
  });
  if (!trace.ok) throw trace.error;
  const viewed = await inspectAnalysisView({
    source: { kind: "inline", evidence: trace.value.evidence },
    view: { kind: "summary" },
  });
  expect(viewed.ok, viewed.ok ? undefined : viewed.error.message).toBe(true);
  if (!viewed.ok) throw viewed.error;
  expect(viewed.value.evidence_links).toContain(
    trace.value.evidence.evidence_id,
  );
  expect(viewed.value.normalized_result).toMatchObject({
    parent_operation: "trace_application_feature",
    summary: {
      trace_id: trace.value.result.trace_id,
      summary: trace.value.result.summary,
    },
  });
  expect(JSON.stringify(viewed.value.normalized_result)).not.toContain(
    '"observations":',
  );
});

it.each([
  "nodes",
  "edges",
  "paths",
  "seed_matches",
  "native_handoffs",
] as const)(
  "pages retained %s with original indices and minimal fields",
  async (collection) => {
    const fixture = applicationFeatureViewFixture({ partial: true });
    const expected =
      collection === "nodes"
        ? fixture.result.graph?.nodes
        : collection === "edges"
          ? fixture.result.graph?.edges
          : fixture.result[collection];
    if (expected === undefined) throw new Error("Expected graph rows");
    expect(expected.length).toBeGreaterThan(0);
    const before = JSON.stringify(fixture.evidence);
    const rows = [];
    for (let offset = 0; offset < expected.length; offset++) {
      const selected = await inspectAnalysisView(
        {
          source: {
            kind: "retained-evidence",
            evidence_id: fixture.evidence.evidence_id,
          },
          view: {
            kind: "application-feature",
            collection,
            fields: [],
            offset,
            limit: 1,
          },
        },
        (id) =>
          id === fixture.evidence.evidence_id ? fixture.evidence : undefined,
      );
      if (!selected.ok) throw selected.error;
      const page = analysisViewResultSchema.parse(
        selected.value.normalized_result,
      );
      if (page.kind !== "application-feature")
        throw new Error("Expected feature page");
      expect(page.source_coverage.status).toBe("partial");
      expect(page.coverage).toMatchObject({
        examined: 1,
        total: expected.length,
        next_offset: offset + 1 < expected.length ? offset + 1 : null,
        exhausted: offset + 1 === expected.length,
      });
      expect(page.items[0]).toMatchObject({ source_index: offset });
      expect(JSON.stringify(page.items)).not.toContain('"properties":');
      rows.push(...page.items);
    }
    expect(rows).toHaveLength(expected.length);
    expect(JSON.stringify(fixture.evidence)).toBe(before);
  },
);

it("preserves absence of semantic discovery and a retained discovery window separately", async () => {
  const fixture = applicationFeatureViewFixture({ noMatch: true });
  const view = {
    kind: "application-feature",
    collection: "semantic_matches",
    limit: 1,
  };
  const absent = await inspectAnalysisView({
    source: { kind: "inline", evidence: fixture.evidence },
    view,
  });
  if (!absent.ok) throw absent.error;
  expect(absent.value.normalized_result).toMatchObject({
    graph_context: null,
    semantic_discovery: null,
    source_coverage: { status: "no-match" },
    items: [],
    coverage: { total: 0 },
  });
  const nodeId = `jsrg_node_${"1".repeat(64)}`;
  const result = {
    ...fixture.result,
    semantic_discovery: {
      source_graph_id: `jsrg_${"2".repeat(64)}`,
      source_coverage: "partial" as const,
      total: 4,
      offset: 2,
      limit: 1,
      next_offset: 3,
      matches: [
        {
          node_id: nodeId,
          kind: "call",
          trace_seed: { kind: "semantic-node" as const, node_id: nodeId },
        },
      ],
    },
  };
  const evidence = createApplicationFeatureTraceEvidence({}, result);
  const selected = await inspectAnalysisView({
    source: { kind: "inline", evidence },
    view,
  });
  if (!selected.ok) throw selected.error;
  expect(selected.value.normalized_result).toMatchObject({
    semantic_discovery: {
      total: 4,
      offset: 2,
      next_offset: 3,
      retained_matches: 1,
    },
    items: [{ node_id: nodeId, source_index: 0 }],
    coverage: { exhausted: true, total: 1, next_offset: null },
  });
});

it("selects explicit fields and retains mandatory identity while rejecting foreign fields", async () => {
  const fixture = applicationFeatureViewFixture();
  const selected = await inspectAnalysisView({
    source: { kind: "inline", evidence: fixture.evidence },
    view: {
      kind: "application-feature",
      collection: "nodes",
      fields: ["kind", "identity"],
      limit: 1,
    },
  });
  if (!selected.ok) throw selected.error;
  const page = analysisViewResultSchema.parse(selected.value.normalized_result);
  if (page.kind !== "application-feature") throw new Error("Expected page");
  expect(page.items[0]).toEqual({
    source_index: 0,
    node_id: fixture.result.graph?.nodes[0]?.node_id,
    kind: fixture.result.graph?.nodes[0]?.kind,
    identity: fixture.result.graph?.nodes[0]?.identity,
  });
  expect(
    inspectAnalysisViewInputSchema.safeParse({
      source: {
        kind: "retained-evidence",
        evidence_id: fixture.evidence.evidence_id,
      },
      view: {
        kind: "application-feature",
        collection: "edges",
        fields: ["observations"],
      },
    }).success,
  ).toBe(false);
  const beyond = await inspectAnalysisView({
    source: { kind: "inline", evidence: fixture.evidence },
    view: {
      kind: "application-feature",
      collection: "nodes",
      offset: 1000,
      limit: 1,
    },
  });
  if (!beyond.ok) throw beyond.error;
  expect(beyond.value.normalized_result).toMatchObject({
    items: [],
    coverage: { exhausted: true, next_offset: null },
  });
});
