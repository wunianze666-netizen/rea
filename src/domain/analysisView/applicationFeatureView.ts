import { z } from "zod";
import {
  type ApplicationFeatureTraceResult,
  applicationFeatureTraceResultSchema,
} from "../javascript/javascriptFeatureTraceSchemas.js";
import {
  applicationNodeSchema,
  applicationEdgeSchema,
} from "../javascript/javascriptApplicationGraphSchemas.js";
import { applicationCoverageSchema } from "../javascript/javascriptApplicationEvidenceSchemas.js";
import type { JsonValue } from "../jsonValue.js";
import { err, ok } from "../result.js";
import {
  createAnalysisViewResultReader,
  type AnalysisViewParent,
} from "./analysisViewParent.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import {
  ownedView,
  type AdmittedView,
  type SummaryAnalysisView,
} from "./analysisViewShape.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
  pageViewCoverage,
} from "./analysisViewCoverage.js";
import { selectViewRows } from "./selectViewRows.js";

const trace = applicationFeatureTraceResultSchema.shape;
const index = z.int().nonnegative();
const nodes = applicationNodeSchema.extend({
  source_index: index,
  observation_count: index,
  root: z.boolean(),
});
const edges = applicationEdgeSchema.extend({ source_index: index });
const paths = trace.paths.element.extend({ source_index: index });
const seeds = trace.seed_matches.element.extend({ source_index: index });
const handoffs = trace.native_handoffs.element.extend({ source_index: index });
const discovery = trace.semantic_discovery.unwrap();
const matches = discovery.shape.matches.element.extend({ source_index: index });
const page = {
  kind: z.literal("application-feature"),
  offset: index.default(0),
  limit: z.int().positive().default(64),
};

/** Pages select already retained rows; they never change feature traversal or semantic discovery. */
export const applicationFeatureViewRequestSchema = z.discriminatedUnion(
  "collection",
  [
    z.strictObject({
      ...page,
      collection: z.literal("nodes"),
      fields: z.array(nodes.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("edges"),
      fields: z.array(edges.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("paths"),
      fields: z.array(paths.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("seed_matches"),
      fields: z.array(seeds.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("native_handoffs"),
      fields: z.array(handoffs.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("semantic_matches"),
      fields: z.array(matches.keyof()).optional(),
    }),
  ],
);
export const applicationFeatureViewItemsSchema = z.union([
  z.array(nodes.partial().required({ source_index: true, node_id: true })),
  z.array(
    edges.partial().required({
      source_index: true,
      edge_id: true,
      source_node_id: true,
      target_node_id: true,
    }),
  ),
  z.array(paths.partial().required({ source_index: true, path_id: true })),
  z.array(seeds.partial().required({ source_index: true, node_id: true })),
  z.array(
    handoffs.partial().required({ source_index: true, native_node_id: true }),
  ),
  z.array(matches.partial().required({ source_index: true, node_id: true })),
]);
export const applicationFeatureViewContextSchema =
  applicationFeatureTraceResultSchema
    .pick({
      trace_id: true,
      source_evidence_id: true,
      source_graph_id: true,
      seed: true,
      direction: true,
      summary: true,
      evidence_links: true,
    })
    .extend({
      source_coverage: trace.coverage,
      graph_context: z
        .strictObject({
          graph_id: trace.source_graph_id,
          root_node_count: index,
          retained_nodes: index,
          retained_edges: index,
          coverage: applicationCoverageSchema,
        })
        .nullable(),
      semantic_discovery: discovery
        .omit({ matches: true })
        .extend({ retained_matches: index })
        .nullable(),
    });

const readTrace = createAnalysisViewResultReader(
  applicationFeatureTraceResultSchema,
);
const everyRow = () => true;
const columns = (
  row: object,
  fields: readonly string[],
): Record<string, JsonValue> => {
  const source = row as Record<string, JsonValue>;
  return Object.fromEntries(fields.map((field) => [field, source[field]!]));
};

/** Keep source completeness separate from exhaustion of a selected retained collection. */
export const projectApplicationFeatureView = (
  parent: AnalysisViewParent,
  admitted: AdmittedView,
) => {
  const view = ownedView<
    SummaryAnalysisView | z.output<typeof applicationFeatureViewRequestSchema>
  >(admitted, "summary", "application-feature");
  if (view === undefined)
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message:
            "Application feature traces support summary and application-feature pages",
        },
      ]),
    );
  const parsed = readTrace(parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  const context = {
    trace_id: report.trace_id,
    source_evidence_id: report.source_evidence_id,
    source_graph_id: report.source_graph_id,
    seed: report.seed,
    direction: report.direction,
    summary: report.summary,
    source_coverage: report.coverage,
    evidence_links: report.evidence_links,
    graph_context:
      report.graph === null
        ? null
        : {
            graph_id: report.graph.graph_id,
            root_node_count: report.graph.root_node_ids.length,
            retained_nodes: report.graph.nodes.length,
            retained_edges: report.graph.edges.length,
            coverage: report.graph.coverage,
          },
    semantic_discovery:
      report.semantic_discovery === undefined
        ? null
        : {
            source_graph_id: report.semantic_discovery.source_graph_id,
            source_coverage: report.semantic_discovery.source_coverage,
            total: report.semantic_discovery.total,
            offset: report.semantic_discovery.offset,
            limit: report.semantic_discovery.limit,
            next_offset: report.semantic_discovery.next_offset,
            retained_matches: report.semantic_discovery.matches.length,
          },
  };
  const shared = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "trace_application_feature" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: null,
    limitations: boundedViewMessages(
      [
        ...parent.limitations,
        ...report.limitations,
        ...(report.graph?.limitations ?? []),
      ],
      parent.evidenceId,
      "limitations",
    ),
    unknowns: [
      "Exhaustion covers selected retained rows only; it does not upgrade source coverage or rerun feature traversal or semantic discovery.",
    ],
  };
  if (view.kind === "summary")
    return ok({
      ...shared,
      kind: "summary" as const,
      view,
      summary: context,
      coverage: completeWithinViewCoverage(1, 1),
    });
  const { items, total } = projectRows(report, view);
  return ok({
    ...shared,
    ...context,
    kind: "application-feature" as const,
    view,
    items,
    coverage: pageViewCoverage(view.offset, items.length, total),
  });
};

const projectRows = (
  report: ApplicationFeatureTraceResult,
  view: z.output<typeof applicationFeatureViewRequestSchema>,
) => {
  let items: z.output<typeof applicationFeatureViewItemsSchema>;
  let total: number;
  switch (view.collection) {
    case "nodes": {
      const roots = new Set(report.graph?.root_node_ids ?? []);
      const selected = selectViewRows(
        report.graph?.nodes ?? [],
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(
            {
              ...row,
              observation_count: row.observations.length,
              root: roots.has(row.node_id),
            },
            view.fields ?? ["kind", "observation_count", "root"],
          ),
          source_index,
          node_id: row.node_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
    case "edges": {
      const selected = selectViewRows(
        report.graph?.edges ?? [],
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(row, view.fields ?? ["relation"]),
          source_index,
          edge_id: row.edge_id,
          source_node_id: row.source_node_id,
          target_node_id: row.target_node_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
    case "paths": {
      const selected = selectViewRows(
        report.paths,
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(
            row,
            view.fields ?? [
              "start_node_id",
              "end_node_id",
              "end_kind",
              "contains_inference",
            ],
          ),
          source_index,
          path_id: row.path_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
    case "seed_matches": {
      const selected = selectViewRows(
        report.seed_matches,
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(row, view.fields ?? ["kind", "basis", "field"]),
          source_index,
          node_id: row.node_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
    case "native_handoffs": {
      const selected = selectViewRows(
        report.native_handoffs,
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(row, view.fields ?? ["status", "artifact_sha256"]),
          source_index,
          native_node_id: row.native_node_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
    case "semantic_matches": {
      const selected = selectViewRows(
        report.semantic_discovery?.matches ?? [],
        view,
        everyRow,
        (row, source_index) => ({
          ...columns(row, view.fields ?? ["kind", "trace_seed"]),
          source_index,
          node_id: row.node_id,
        }),
      );
      items = selected.rows;
      total = selected.total;
      break;
    }
  }
  return { items, total };
};
