import { expect, it } from "vitest";
import { EnhancedTools } from "./EnhancedTools.js";
import {
  createAnalysisExecution,
  type AnalysisOperationPort,
} from "./AnalysisProvider.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { createEvidence } from "../domain/evidence.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { err, ok } from "../domain/result.js";

const provider = { id: "fixture", name: "Fixture", version: "1" };
const tools = ["get_call_graph", "trace_call_path"] as const;
const directions = ["forward", "backward"] as const;
const states = ["pending", "unbound", "plain", "resolved"] as const;
const cases = tools.flatMap((tool) =>
  directions.flatMap((direction) =>
    states.map((state) => ({ tool, direction, state, cancel: false })),
  ),
);
const cancelled = tools.flatMap((tool) =>
  directions.map((direction) => ({
    tool,
    direction,
    state: "pending" as const,
    cancel: true,
  })),
);

it.each([...cases, ...cancelled])(
  "$tool $direction keeps $state cleanup ownership with concurrent cancellation=$cancel",
  async ({ tool, direction, state, cancel }) => {
    const operation =
      direction === "forward" ? "procedure_callees" : "procedure_callers";
    const controller = new AbortController();
    const cause = { stage: "synthetic relationship failure" };
    const partial = createEvidence(undefined, provider, {
      operation,
      parameters: { procedure: "0x2" },
      result: { retained: "provider observation" },
    });
    let resources = ["owned synthetic worker"];
    const failure = new AnalysisCapabilityUnavailableError(
      provider.id,
      operation,
      "read failed",
      {
        cause,
        partialObservation: partial,
        ...(state === "plain"
          ? {}
          : { cleanup: { reason: "worker stop unconfirmed", resources } }),
      },
    );
    if (state === "pending" || state === "resolved") {
      failure.bindCleanupResourceOwner({
        get cleanupResources() {
          return resources;
        },
      });
      failure.bindCleanupRetry({ operation: "close_binary" });
    }
    const release = () => {
      resources = [];
      failure.resolveCleanup();
    };
    if (state === "resolved") release();
    const reads: string[] = [];
    const analysis: AnalysisOperationPort = {
      execute: async (name, parameters) => {
        const address = String(parameters.procedure);
        if (name === "procedure_address")
          return ok(createAnalysisExecution(address, provider));
        if (name !== operation)
          throw new Error(`Unexpected operation: ${name}`);
        reads.push(address);
        if (address === "0x2") {
          if (cancel) controller.abort({ requested: "stop during failure" });
          return err(failure);
        }
        return ok(
          createAnalysisExecution(
            address === "0x1"
              ? ["0x2", "0x3"]
              : address === "0x3"
                ? ["0x4"]
                : [],
            provider,
            {
              relationshipCoverage: {
                status: "complete",
              },
            },
          ),
        );
      },
    };
    const result = await new EnhancedTools(analysis).execute(
      tool,
      tool === "get_call_graph"
        ? { address: "0x1", direction }
        : { start: "0x1", goal: "0x4", direction },
      controller.signal,
    );
    if (state === "plain" || state === "resolved") {
      expect(result.ok).toBe(true);
      expect(reads).toContain("0x3");
      if (tool === "trace_call_path" && result.ok)
        expect(result.value).toMatchObject({ goal_status: "reached" });
      return;
    }
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Unconfirmed cleanup must stop traversal");
    expect(result.error).toBe(failure);
    expect(reads).toEqual(["0x1", "0x2"]);
    expect(result.error.cause).toBe(cause);
    expect(result.error.partialObservation).toBe(partial);
    expect(result.error.cleanupResources).toEqual(["owned synthetic worker"]);
    expect(result.error.cleanupRetry).toEqual(
      state === "unbound" ? undefined : { operation: "close_binary" },
    );
    const history = projectAnalysisError(result.error);
    expect(history.code).toBe("cleanup_incomplete");
    release();
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(result.error.cleanupRetry).toBeUndefined();
    expect(history.code).toBe("cleanup_incomplete");
  },
);
