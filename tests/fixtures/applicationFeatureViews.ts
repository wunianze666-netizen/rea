import {
  analysisViewBindJavaScriptGraphs,
  analysisViewJavaScriptAnalysis,
  analysisViewJavaScriptEvidence,
} from "./analysisView.js";
import { buildSyntheticJavaScriptApplicationGraph } from "../../src/domain/javascript/javascriptApplicationGraph.fixture.js";
import {
  createJavaScriptApplicationGraph,
  createJavaScriptApplicationNode,
} from "../../src/domain/javascript/javascriptApplicationGraph.js";
import { traceApplicationFeatureEvidence } from "../../src/application/javascript/JavaScriptApplicationWorkflowService.js";

/** Authored graph observations, passed through the actual feature-trace producer. No target is opened. */
export const applicationFeatureViewFixture = (
  options: { payloadBytes?: number; partial?: boolean; noMatch?: boolean } = {},
) => {
  const original = buildSyntheticJavaScriptApplicationGraph();
  const base = analysisViewJavaScriptAnalysis();
  const graph = createJavaScriptApplicationGraph({
    schema: original.schema,
    root_node_ids: [...original.root_node_ids, ...base.graph.root_node_ids],
    nodes: [
      ...original.nodes.map((node) =>
        createJavaScriptApplicationNode({
          kind: node.kind,
          identity: node.identity,
          observations: node.observations.map((observation, index) => ({
            label: observation.label,
            source_map_reference: observation.source_map_reference,
            properties: {
              ...observation.properties,
              ...(node.kind === "ipc-channel" &&
              index === 0 &&
              options.payloadBytes !== undefined
                ? { view_fixture_payload: "x".repeat(options.payloadBytes) }
                : {}),
            },
            evidence: observation.evidence,
          })),
        }),
      ),
      ...base.graph.nodes,
    ],
    edges: [...original.edges, ...base.graph.edges],
    coverage: options.partial
      ? {
          status: "partial",
          truncated: true,
          omitted_count: 1,
          limits: [
            {
              name: "fixture-omission",
              value: original.nodes.length,
              unit: "items",
            },
          ],
        }
      : original.coverage,
    limitations: original.limitations,
  });
  const application = analysisViewBindJavaScriptGraphs(base, graph);
  const source = analysisViewJavaScriptEvidence(application);
  const trace = traceApplicationFeatureEvidence({
    application: source,
    seed: options.noMatch
      ? { kind: "node-id", value: `jag_node_${"f".repeat(64)}` }
      : { kind: "channel", value: "project:open", match: "exact" },
    direction: "both",
  });
  if (!trace.ok) throw trace.error;
  return { source, ...trace.value };
};
