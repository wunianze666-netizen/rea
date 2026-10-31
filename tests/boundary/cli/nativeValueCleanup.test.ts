import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Cli } from "incur";
import pino from "pino";
import { afterEach, expect, it } from "vitest";
import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import type { DirectAnalysisDependencies } from "../../../src/application/DirectAnalysisDependencies.js";
import { registerCoreNativeCommands } from "../../../src/cli/coreNativeCommands.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { analysisCliErrorEnvelopeSchema } from "../../../src/contracts/errorSchemas.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import type { Evidence } from "../../../src/domain/evidence.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { z } from "zod";
import { ok } from "../../../src/domain/result.js";
import {
  nativeCleanupIdentity,
  nativeValueCleanupFixture,
} from "../../fixtures/nativeValueCleanup.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const sessions: ReturnType<typeof createTestBinarySession>[] = [];
const fixtures: ReturnType<typeof nativeValueCleanupFixture>[] = [];
afterEach(async () => {
  for (const fixture of fixtures.splice(0)) fixture.proveCleanup();
  for (const session of sessions.splice(0)) {
    const closed = await session.close();
    if (!closed.ok) throw closed.error;
  }
});
const cases = (["resolve", "callee"] as const).flatMap((phase) =>
  [false, true].map((closeCanProve) => ({ phase, closeCanProve })),
);

it.each(cases)(
  "registered native trace CLI preserves $phase failure when final close can prove cleanup=$closeCanProve",
  async ({ phase, closeCanProve }) => {
    const root = await createTestTempDirectory("rea-native-cleanup-cli-");
    const path = join(root, "fixture.hop");
    await writeFile(path, "synthetic analysis database");
    const fixture = nativeValueCleanupFixture({
      phase,
      closeCanProve,
      supplyPartial: false,
    });
    fixtures.push(fixture);
    let records: readonly Evidence[] = [];
    const createSession = () => {
      let session: ReturnType<typeof createTestBinarySession>;
      session = createTestBinarySession(
        fixture.provider([], () => {
          records = session.exportEvidenceBundle().records;
        }),
        {
          resolveAnalysisProfile: async () =>
            ok({
              profile: createAnalysisProfile(nativeCleanupIdentity, {
                fixture: true,
              }),
            }),
        },
      );
      sessions.push(session);
      return session;
    };
    const dependencies: DirectAnalysisDependencies = {
      readConfiguration: () => parseConfig({}),
      createBinarySession: createSession,
      createNativeDispatchBinarySession: createSession,
      createArtifactBinarySession: createSession,
      createNativeBinarySession: createSession,
      createManagedBinarySession: createSession,
    };
    const cli = Cli.create("rea-native-cleanup-test", { sync: false });
    registerCoreNativeCommands(
      cli,
      pino({ enabled: false }),
      (target, tool, arguments_, options) =>
        runDirectAnalysis(dependencies, target, tool, arguments_, options),
    );
    let stdout = "";
    await cli.serve(
      ["trace-native-values", path, "0x1000", "--max-depth", "1", "--json"],
      {
        env: {},
        stdout: (text) => {
          stdout += text;
        },
        exit: () => undefined,
      },
    );
    const failure = fixture.failure();
    const partial = fixture.partial();
    expect(failure).toBeDefined();
    expect(partial).toBeDefined();
    if (failure === undefined || partial === undefined)
      throw new Error(
        "Expected the original late provider failure and seed observation",
      );
    const error = analysisCliErrorEnvelopeSchema.parse(JSON.parse(stdout));
    expect(error.code).toBe(
      closeCanProve ? "capability_unavailable" : "cleanup_incomplete",
    );
    const captured = parseEvidence(
      z.record(z.string(), z.unknown()).parse(error.details)
        .partial_observation,
    );
    const address = phase === "resolve" ? "0x1000" : "0x2000";
    const completed = records.find(
      (record) =>
        record.operation === "analyze_function" &&
        record.parameters.procedure === address,
    );
    expect(completed).toBeDefined();
    expect(captured).toMatchObject({
      operation: "analyze_function",
      parameters: { procedure: address },
    });
    expect(captured.normalized_result).toEqual(completed?.normalized_result);
    expect(
      records.some((record) => record.operation === "trace_native_values"),
    ).toBe(false);
    expect(
      records.find(
        (record) =>
          record.operation === "analyze_function" &&
          record.parameters.procedure === "0x1000",
      )?.normalized_result,
    ).toEqual(partial.normalized_result);
    expect(fixture.calls).not.toContain("analyze_function:0x4000");
    const calls = [...fixture.calls];
    expect(failure.cleanupIncomplete).toBe(!closeCanProve);
    fixture.proveCleanup();
    for (const session of sessions)
      expect((await session.close()).ok).toBe(true);
    expect(failure.cleanupIncomplete).toBe(false);
    expect(fixture.calls).toEqual(calls);
  },
);
