import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { createJavaScriptRuntimeObservationEvidence } from "../../../src/application/javascript/JavaScriptRuntimeObservationEvidence.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import {
  reconcileJavaScriptRuntimeInputSchema,
  javascriptRuntimeReconciliationResultSchema,
} from "../../../src/domain/javascript/javascriptRuntimeReconciliationSchemas.js";
import { javascriptRuntimeObservationSchema } from "../../../src/domain/javascript/javascriptRuntimeObservation.js";
import { V8_INSPECTOR_PROVIDER_IDENTITY } from "../../../src/inspector/providerIdentity.js";
import { analyzeFixture } from "../../fixtures/javascriptRuntimeReconciliation.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

/** Authored retained metadata for offline reconciliation; no host admission or live capture is claimed. */
const runtimeEvidence = (
  root: string,
  role: "node" | "electron-main",
  scripts: boolean,
) => {
  const entries = scripts
    ? [
        {
          script_key: `v8_script_${"1".repeat(64)}`,
          location: { kind: "file", file_path: join(root, "app.mjs") },
          execution_context_key: "1",
          cdp_hash: null,
          length: null,
          is_module: true,
          status: "observed-loaded",
        },
        {
          script_key: `v8_script_${"2".repeat(64)}`,
          location: { kind: "builtin", specifier: "node:fs" },
          execution_context_key: "1",
          cdp_hash: null,
          length: null,
          is_module: null,
          status: "observed-loaded",
        },
      ]
    : [];
  const result = javascriptRuntimeObservationSchema.parse({
    runtime: {
      product: "node.js/v24.22.1",
      protocol_version: "1.3",
      v8_version: null,
    },
    target: {
      target_id: "retained-node-target",
      protocol_type: "node",
      attached: null,
      location: { kind: "file", file_path: join(root, "app.mjs") },
      runtime_kind: role,
      runtime_kind_authority: "caller-declared-unverified",
    },
    capture: {
      observation_ms: 0,
      events_observed: entries.length,
      events_retained: entries.length,
      events_dropped: 0,
      metadata_bytes_retained: 0,
      truncated: false,
      truncation_reasons: [],
    },
    scripts: {
      items: entries,
      observed_total: entries.length,
      excluded: { unsupported_location: 0, invalid_protocol_value: 0 },
    },
    execution_contexts: [],
    directly_observed: ["Authored retained Inspector metadata fixture."],
    unavailable_without_instrumentation: [
      "Script source bytes and execution edges were not captured.",
    ],
    unknowns: [
      "The bounded fixture does not establish complete script inventory.",
    ],
    limitations: [
      "Authored retained metadata for offline reconciliation, not a live Node/Electron observation.",
    ],
  });
  return createJavaScriptRuntimeObservationEvidence(
    "observe_javascript_runtime",
    {
      inspector_endpoint: "http://127.0.0.1:9229",
      target_id: result.target.target_id,
      runtime_kind: role,
      observation_ms: 0,
    },
    result,
    V8_INSPECTOR_PROVIDER_IDENTITY,
  );
};

cliTest.for(["CLI", "stdio MCP"] as const)(
  "reconciles Node entry identity without inventing script presence through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-node-target-");
    const cache = await createTestTempDirectory("rea-node-target-cache-");
    await Promise.all([
      writeFile(join(root, "app.mjs"), "export const application = true;\n"),
      writeFile(join(root, "unused.mjs"), "export const unused = true;\n"),
      writeFile(join(cache, "app.mjs"), "export const different = true;\n"),
    ]);
    const analysis = await analyzeFixture(root);
    const cachedAnalysis = await analyzeFixture(cache);
    const layer = { role: "application" as const, analysis };
    const call =
      surface === "stdio MCP"
        ? (await connectLocalToolsMcp({ REA_MCP_MAX_INPUT_ELEMENTS: "8192" }))
            .call
        : undefined;
    const reconcile = async (input: unknown) => {
      const request = reconcileJavaScriptRuntimeInputSchema.parse(input);
      let evidence: unknown;
      if (call === undefined) {
        const inputPath = join(root, "reconciliation.json");
        await writeFile(inputPath, JSON.stringify(request));
        const output = await cli.run({
          arguments: ["reconcile-javascript-runtime", inputPath, "--json"],
        });
        expect(output.exitCode, output.stderr).toBe(0);
        evidence = output.json;
      } else {
        const output = await call("reconcile_javascript_runtime", request);
        expect(output.isError, JSON.stringify(output)).not.toBe(true);
        evidence = output.structuredContent;
      }
      return javascriptRuntimeReconciliationResultSchema.parse(
        parseEvidence(evidence).normalized_result,
      );
    };
    const targetOf = (result: Awaited<ReturnType<typeof reconcile>>) => {
      const target = result.reconciliations.find(
        ({ entity_kind }) => entity_kind === "target",
      );
      if (target === undefined)
        throw new Error("Missing target reconciliation");
      return target;
    };
    for (const role of ["node", "electron-main"] as const) {
      const runtime = runtimeEvidence(root, role, true);
      const result = await reconcile({
        static_layers: [layer],
        runtime_observations: [runtime],
      });
      const target = targetOf(result);
      expect(target).toMatchObject({
        status: "matched",
        basis: "artifact-path",
        confidence: "medium",
        reason: "unique-location-match",
        candidate_static_count: 1,
      });
      expect(
        result.graph.nodes.find(
          ({ node_id }) => node_id === target.static_node_id,
        )?.kind,
      ).toBe("javascript-asset");
      expect(result.reconciliations).toContainEqual(
        expect.objectContaining({ entity_kind: "script", status: "matched" }),
      );
      expect(result.reconciliations).toContainEqual(
        expect.objectContaining({
          entity_kind: "script",
          status: "unknown",
          reason: "no-authorized-location-mapping",
        }),
      );
      expect(
        result.static_load_states.every(
          ({ runtime_node_ids }) =>
            !runtime_node_ids.includes(target.runtime_node_id),
        ),
      ).toBe(true);
    }
    const noScripts = runtimeEvidence(root, "node", false);
    const discoveryOnly = await reconcile({
      static_layers: [layer],
      runtime_observations: [noScripts],
    });
    expect(targetOf(discoveryOnly).status).toBe("matched");
    expect(discoveryOnly.summary.static_loaded).toBe(0);
    expect(
      discoveryOnly.static_load_states.every(
        ({ status, runtime_node_ids }) =>
          status === "unknown" && runtime_node_ids.length === 0,
      ),
    ).toBe(true);
    const ambiguous = await reconcile({
      static_layers: [
        layer,
        {
          role: "cache",
          analysis: cachedAnalysis,
          runtime_mappings: [{ kind: "file-root", root, artifact_prefix: "" }],
        },
      ],
      runtime_observations: [noScripts],
    });
    const ambiguousTarget = targetOf(ambiguous);
    expect(ambiguousTarget).toMatchObject({
      status: "ambiguous",
      reason: "ambiguous-static-candidates",
      candidate_static_count: 2,
    });
    expect(
      ambiguous.graph.edges.filter(
        ({ target_node_id, relation }) =>
          target_node_id === ambiguousTarget.runtime_node_id &&
          relation === "observed_as",
      ),
    ).toEqual([]);
    const unmapped = await reconcile({
      static_layers: [layer],
      runtime_observations: [runtimeEvidence(cache, "node", false)],
    });
    expect(targetOf(unmapped)).toMatchObject({
      status: "unknown",
      reason: "no-authorized-location-mapping",
      candidate_static_count: 0,
    });
  },
);
