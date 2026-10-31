import { expect, it } from "vitest";
import { traceNativeValues } from "./NativeValueTrace.js";
import { nativeValueTraceSchema } from "../../domain/native/nativeValueTrace.js";
import { parseEvidence } from "../../domain/evidence.js";
import { functionDossierSchema } from "../../domain/native/functionDossier.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { nativeValueCleanupFixture } from "../../../tests/fixtures/nativeValueCleanup.js";

const phases = ["seed", "resolve", "callee"] as const;
const states = ["pending", "unbound", "plain", "resolved"] as const;
const cases = phases.flatMap((phase) =>
  states.map((state) => ({ phase, state, cancel: false })),
);

it.each(["resolve", "callee"] as const)(
  "keeps the latest validated dossier when a %s cleanup failure supplies no partial observation",
  async (phase) => {
    const fixture = nativeValueCleanupFixture({ phase, supplyPartial: false });
    const result = await traceNativeValues(fixture.port, {
      procedure: "0x1000",
      max_depth: 1,
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected cleanup failure");
    expect(result.error).toBe(fixture.failure());
    expect(result.error.partialObservation).toBeDefined();
    const partial = parseEvidence(result.error.partialObservation);
    const address = phase === "resolve" ? "0x1000" : "0x2000";
    expect(partial).toMatchObject({
      operation: "analyze_function",
      parameters: { procedure: address },
    });
    expect(
      functionDossierSchema.parse(partial.normalized_result).procedure.address,
    ).toBe(address);
    expect(fixture.calls).not.toContain("analyze_function:0x4000");
  },
);
const cancelled = phases.map((phase) => ({
  phase,
  state: "pending" as const,
  cancel: true,
}));

it.each([...cases, ...cancelled])(
  "native trace preserves $state cleanup at $phase with concurrent cancellation=$cancel",
  async ({ phase, state, cancel }) => {
    const controller = new AbortController();
    const fixture = nativeValueCleanupFixture({
      phase,
      state,
      onFailure: (error) => {
        if (state === "pending")
          error.bindCleanupRetry({ operation: "close_binary" });
        if (cancel) controller.abort({ stop: "during native failure" });
      },
    });
    const result = await traceNativeValues(
      fixture.port,
      { procedure: "0x1000", max_depth: 1 },
      controller.signal,
    );
    const failure = fixture.failure();
    expect(failure).toBeDefined();
    if (failure === undefined)
      throw new Error("Expected the injected provider failure");
    if (phase !== "seed" && (state === "plain" || state === "resolved")) {
      expect(result.ok).toBe(true);
      if (!result.ok) throw result.error;
      expect(
        nativeValueTraceSchema.parse(result.value).unknowns,
      ).toContainEqual(expect.objectContaining({ reason: failure.message }));
      expect(fixture.calls).toContain("analyze_function:0x4000");
      return;
    }
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a terminal provider failure");
    expect(result.error).toBe(failure);
    expect(result.error.cause).toBe(fixture.cause);
    expect(result.error.partialObservation).toBe(fixture.partial());
    expect(fixture.calls).not.toContain("analyze_function:0x4000");
    if (phase === "resolve")
      expect(fixture.calls).not.toContain("resolve_native_call_targets:0x1008");
    if (phase !== "seed") expect(fixture.partial()).toBeDefined();
    if (state === "plain" || state === "resolved") return;
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "cleanup_incomplete",
      details: { resources: ["owned native fixture worker"] },
    });
    expect(result.error.cleanupRetry).toEqual(
      state === "pending" ? { operation: "close_binary" } : undefined,
    );
  },
);
