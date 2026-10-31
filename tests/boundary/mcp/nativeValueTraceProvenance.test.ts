import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { digestCanonicalValue } from "../../../src/domain/canonicalDigest.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import { projectCliAnalysisResult } from "../../../src/cli/projectCliAnalysisResult.js";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterEach, expect, it } from "vitest";
import { z } from "zod";
import type { AnalysisProvider } from "../../../src/application/AnalysisProvider.js";
import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import { SNAPSHOT_REPLAY_LIMITATION } from "../../../src/application/binary/AnalysisSnapshotCache.js";
import { parseEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { evidenceBundleSchema } from "../../../src/domain/evidenceBundle.js";
import { ghidraFunctionDossier } from "../../../src/domain/ghidraValues.fixture.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { functionDossierSchema } from "../../../src/domain/native/functionDossier.js";
import { nativeValueTraceSchema } from "../../../src/domain/native/nativeValueTrace.js";
import { ok } from "../../../src/domain/result.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { createSessionMcpHarness } from "./sessionMcpHarness.js";

const resources: Array<{ close(): Promise<unknown> }> = [];
afterEach(async () => {
  for (const resource of resources.splice(0)) await resource.close();
});

const identity = {
  id: "fixture",
  name: "Fixture analysis provider",
  version: "1",
};
const scalar = {
  kind: "constant",
  size_bytes: 4,
  location: null,
  constant_hex: "3",
};
const baseDossier = functionDossierSchema.parse(ghidraFunctionDossier());
const dossier = functionDossierSchema.parse({
  ...baseDossier,
  procedure: {
    ...baseDossier.procedure,
    address: "0x1000",
    name: "fixture",
    body: { available: false, reason: "Synthetic fixture has no body ranges" },
  },
  native_value_flow: {
    available: true,
    provenance: "ghidra-high-pcode",
    operations: ["COPY", "RETURN"].map((opcode, sequence) => ({
      id: String(sequence),
      address: `0x${(0x1000 + sequence * 4).toString(16)}`,
      sequence,
      opcode,
      is_dead: false,
      block_membership: "member",
      inputs: [scalar, scalar],
      output: scalar,
    })),
    def_use: [{ definition: "0", use: "1", input_index: 1 }],
    parameters: [{ ordinal: 0, name: "value", data_type: "/int" }],
    parameter_uses: [{ ordinal: 0, use: "0", input_index: 0 }],
    effects: [],
    truncated: false,
    omitted_operations_lower_bound: 0,
    known_omitted_inputs: 0,
    known_omitted_edges: 0,
    limitations: [],
  },
});

const traceProvider = (onClose: () => void = () => {}) => {
  let analyses = 0;
  const provider = (): AnalysisProvider => ({
    identity: () => identity,
    capabilities: () => [
      {
        provider: identity,
        operation: "analyze_function",
        available: true,
        reason: null,
        cachePolicy: "snapshot",
        limitations: [],
        effects: {
          mutatesArtifact: false,
          launchesProcess: false,
          mayShowUi: false,
          mayAccessNetwork: false,
          mayWriteFilesystem: false,
          changesPermissions: false,
          requiresRoot: false,
        },
      },
    ],
    createClient: (target, profile) => ({
      execute: async (operation) => {
        if (operation === "health")
          return ok(createAnalysisExecution(null, identity));
        if (operation !== "analyze_function")
          throw new Error(`Unexpected provider call: ${operation}`);
        analyses += 1;
        return ok(
          createAnalysisExecution(jsonValueSchema.parse(dossier), identity, {
            subject: target,
            ...(profile === undefined ? {} : { analysisProfile: profile }),
          }),
        );
      },
      close: async () => {
        onClose();
        return ok(null);
      },
    }),
  });
  return { provider, analysisCount: () => analyses };
};

const citations = (evidence: Evidence) => {
  const result = nativeValueTraceSchema.parse(evidence.normalized_result);
  return new Set([
    ...result.procedures.map((row) => row.evidence_id),
    ...result.nodes.map((row) => row.evidence_id),
    ...result.edges.map((row) => row.evidence_id),
  ]);
};

const assertClosure = (evidence: Evidence, records: readonly Evidence[]) => {
  const byId = new Map(records.map((record) => [record.evidence_id, record]));
  expect(citations(evidence).size).toBe(1);
  for (const id of citations(evidence)) {
    expect(evidence.evidence_links).toContain(id);
    const source = byId.get(id);
    expect(source, `Unretained trace citation ${id}`).toBeDefined();
    expect(source?.normalized_result).toEqual(jsonValueSchema.parse(dossier));
    expect(source?.subject?.digest.sha256).toBe(
      evidence.subject?.digest.sha256,
    );
  }
};

it("keeps native trace source citations resolvable through warm, saved and resaved snapshots", async () => {
  const root = await createTestTempDirectory("rea-native-trace-provenance-");
  const { provider, analysisCount } = traceProvider();
  const connect = async () => {
    const harness = await createSessionMcpHarness(root, provider, resources);
    const { tools } = await harness.mcp.listTools();
    const call = async (name: string, arguments_: Record<string, unknown>) => {
      const toolDefinition = tools.find((tool) => tool.name === name);
      if (toolDefinition === undefined) throw new Error(`Missing tool ${name}`);
      const response = await harness.mcp.callTool(
        { name, arguments: arguments_ },
        { toolDefinition },
      );
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      if (name === "trace_native_values") {
        const validate = new Ajv2020({
          strict: false,
          validateFormats: false,
        }).compile(
          z.record(z.string(), z.unknown()).parse(toolDefinition.outputSchema),
        );
        expect(
          validate(response.structuredContent),
          JSON.stringify(validate.errors),
        ).toBe(true);
      }
      return response.structuredContent;
    };
    return { ...harness, call };
  };
  const cold = await connect();
  await cold.call("open_binary", { path: cold.first });
  const trace = async (
    client: Awaited<ReturnType<typeof connect>>,
    limit = 100,
  ) =>
    parseEvidence(
      await client.call("trace_native_values", { procedure: "0x1000", limit }),
    );
  const exported = async (
    client: Awaited<ReturnType<typeof connect>>,
    name: string,
  ) => {
    const path = join(root, name);
    await client.call("export_evidence_bundle", { path });
    return {
      path,
      bundle: evidenceBundleSchema.parse(
        JSON.parse(await readFile(path, "utf8")),
      ),
    };
  };
  const first = await trace(cold);
  const originalGraph = nativeValueTraceSchema.parse(first.normalized_result);
  expect(originalGraph).toMatchObject({
    total_nodes: 3,
    total_edges: 2,
    truncated: false,
    unknowns: [],
  });
  const coldExport = await exported(cold, "cold-bundle.json");
  assertClosure(first, coldExport.bundle.records);
  const again = await trace(cold);
  const warmExport = await exported(cold, "warm-bundle.json");
  assertClosure(again, warmExport.bundle.records);
  expect(citations(again)).toEqual(citations(first));
  expect(again.normalized_result).toEqual(first.normalized_result);
  expect(
    again.limitations.some((line) => line.includes(SNAPSHOT_REPLAY_LIMITATION)),
  ).toBe(true);
  const page = await trace(cold, 1);
  expect(nativeValueTraceSchema.parse(page.normalized_result).next_offset).toBe(
    1,
  );
  assertClosure(page, warmExport.bundle.records);
  const pagedNodes = [
    ...nativeValueTraceSchema.parse(page.normalized_result).nodes,
  ];
  const pagedEdges = [
    ...nativeValueTraceSchema.parse(page.normalized_result).edges,
  ];
  for (let offset = 1; offset < originalGraph.total_nodes; offset += 1) {
    const part = parseEvidence(
      await cold.call("trace_native_values", {
        procedure: "0x1000",
        limit: 1,
        offset,
      }),
    );
    assertClosure(part, warmExport.bundle.records);
    const graph = nativeValueTraceSchema.parse(part.normalized_result);
    pagedNodes.push(...graph.nodes);
    pagedEdges.push(...graph.edges);
  }
  expect(pagedNodes).toEqual(originalGraph.nodes);
  expect(pagedEdges.map((edge) => digestCanonicalValue(edge)).sort()).toEqual(
    originalGraph.edges.map((edge) => digestCanonicalValue(edge)).sort(),
  );
  expect(analysisCount()).toBe(1);
  const snapshot = join(root, "original-snapshot.json");
  await cold.call("close_binary", { snapshot_path: snapshot });
  const reopened = await connect();
  await reopened.call("open_binary", {
    path: reopened.first,
    snapshot_path: snapshot,
  });
  const savedReplay = await trace(reopened);
  const savedExport = await exported(reopened, "saved-replay-bundle.json");
  assertClosure(savedReplay, savedExport.bundle.records);
  expect(citations(savedReplay)).toEqual(citations(first));
  const resaved = join(root, "resaved-snapshot.json");
  await reopened.call("close_binary", { snapshot_path: resaved });
  const restored = await connect();
  await restored.call("open_binary", {
    path: restored.first,
    snapshot_path: resaved,
  });
  const resavedReplay = await trace(restored, 1);
  const resavedExport = await exported(restored, "resaved-replay-bundle.json");
  assertClosure(resavedReplay, resavedExport.bundle.records);
  expect(analysisCount()).toBe(1);
  const offline = await connect();
  await offline.call("import_evidence_bundle", { path: resavedExport.path });
  for (const id of citations(resavedReplay)) {
    await offline.call("inspect_analysis_view", {
      source: { kind: "retained-evidence", evidence_id: id },
      view: { kind: "summary" },
    });
  }
  expect(analysisCount()).toBe(1);
}, 60_000);

it("keeps source closure in the CLI application boundary after an earlier dossier call", async () => {
  const root = await createTestTempDirectory("rea-native-trace-cli-source-");
  const path = join(root, "fixture.hop");
  await writeFile(path, "synthetic analysis database");
  let records: readonly Evidence[] = [];
  let session: ReturnType<typeof createTestBinarySession>;
  const { provider, analysisCount } = traceProvider(() => {
    records = session.exportEvidenceBundle().records;
  });
  session = createTestBinarySession(provider(), {
    resolveAnalysisProfile: async () =>
      ok({ profile: createAnalysisProfile(identity, { fixture: true }) }),
  });
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;
  try {
    const original = await session.execute("analyze_function", {
      procedure: "0x1000",
    });
    if (!original.ok) throw original.error;
    expect(original.value.evidenceId).toBeDefined();
    const createSession = () => session;
    const evidence = parseEvidence(
      await runDirectAnalysis(
        {
          readConfiguration: () => parseConfig({}),
          createBinarySession: createSession,
          createNativeDispatchBinarySession: createSession,
          createArtifactBinarySession: createSession,
          createNativeBinarySession: createSession,
          createManagedBinarySession: createSession,
        },
        path,
        "trace_native_values",
        { procedure: "0x1000" },
      ).then(projectCliAnalysisResult),
    );
    const trace = nativeValueTraceSchema.parse(evidence.normalized_result);
    for (const row of [...trace.procedures, ...trace.nodes, ...trace.edges]) {
      expect(row.evidence_id).toBe(original.value.evidenceId);
      expect(evidence.evidence_links).toContain(row.evidence_id);
      expect(
        records.some((record) => record.evidence_id === row.evidence_id),
      ).toBe(true);
    }
    expect(
      evidence.limitations.some((line) =>
        line.includes(SNAPSHOT_REPLAY_LIMITATION),
      ),
    ).toBe(true);
    expect(analysisCount()).toBe(1);
  } finally {
    const closed = await session.close();
    if (!closed.ok) throw closed.error;
  }
});
