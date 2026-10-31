import {
  createAnalysisExecution,
  type AnalysisOperationPort,
  type AnalysisProvider,
  type CapabilityDescriptor,
} from "../../src/application/AnalysisProvider.js";
import {
  pcodeOperation,
  staticValueGraph,
  valueTraceSubject,
} from "../../src/application/native/NativeValueTrace.fixture.js";
import { AnalysisCapabilityUnavailableError } from "../../src/domain/analysisErrorCore.js";
import { createAnalysisExecutionEvidence } from "../../src/domain/analysisObservation.js";
import type {
  Evidence,
  EvidenceSubjectTarget,
} from "../../src/domain/evidence.js";
import type { AnalysisProfileCommitment } from "../../src/domain/analysisProfile.js";
import { err, ok } from "../../src/domain/result.js";

export type NativeCleanupPhase = "seed" | "resolve" | "callee";
export type NativeCleanupState = "pending" | "unbound" | "plain" | "resolved";
export const nativeCleanupIdentity = {
  id: "fixture",
  name: "Fixture analysis provider",
  version: "1",
};
const parameter = [{ ordinal: 0, name: "value", data_type: "/int" }];
const capabilities = (): CapabilityDescriptor[] =>
  (["analyze_function", "resolve_native_call_targets"] as const).map(
    (operation) => ({
      operation,
      provider: nativeCleanupIdentity,
      available: true,
      reason: null,
      cachePolicy: "live",
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
    }),
  );

const nativeGraph = () =>
  staticValueGraph(
    {
      "0x1000": {
        operations: [
          pcodeOperation("call-b", "0x1004", "CALL"),
          pcodeOperation("call-c", "0x1008", "CALL"),
          pcodeOperation("call-d", "0x100c", "CALL"),
        ],
      },
      "0x2000": {
        operations: [pcodeOperation("return-b", "0x2000", "RETURN")],
        parameters: parameter,
      },
      "0x3000": {
        operations: [pcodeOperation("return-c", "0x3000", "RETURN")],
        parameters: parameter,
      },
      "0x4000": {
        operations: [pcodeOperation("return-d", "0x4000", "RETURN")],
        parameters: parameter,
      },
    },
    {
      "0x1004": [{ destination: "0x2000", status: "direct" }],
      "0x1008": [{ destination: "0x3000", status: "direct" }],
      "0x100c": [{ destination: "0x4000", status: "direct" }],
    },
  );

/** Simulated metadata/cleanup owner; real sessions and adapters consume its typed observations. */
export const nativeValueCleanupFixture = (options: {
  readonly phase: NativeCleanupPhase;
  readonly state?: NativeCleanupState;
  readonly onFailure?: (error: AnalysisCapabilityUnavailableError) => void;
  readonly closeCanProve?: boolean;
  readonly supplyPartial?: boolean;
}) => {
  const state = options.state ?? "pending";
  const graph = nativeGraph();
  const calls: string[] = [];
  const cause = { phase: options.phase, fixture: "native value cleanup" };
  let resources: string[] = [];
  let proofAvailable = options.closeCanProve ?? false;
  let failure: AnalysisCapabilityUnavailableError | undefined;
  let partial: Evidence | undefined;
  const portFor = (
    subject: EvidenceSubjectTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisOperationPort => ({
    execute: async (operation, input, execution) => {
      const selector = String(input.procedure ?? input.address);
      calls.push(`${operation}:${selector}`);
      const fail =
        options.phase === "seed"
          ? operation === "analyze_function" && selector === "0x1000"
          : options.phase === "resolve"
            ? operation === "resolve_native_call_targets" &&
              selector === "0x1004"
            : operation === "analyze_function" && selector === "0x3000";
      if (fail) {
        resources =
          state === "plain" || state === "resolved"
            ? []
            : ["owned native fixture worker"];
        failure = new AnalysisCapabilityUnavailableError(
          nativeCleanupIdentity.id,
          operation,
          "synthetic native child failure",
          {
            cause,
            ...(partial === undefined || options.supplyPartial === false
              ? {}
              : { partialObservation: partial }),
            ...(state === "plain"
              ? {}
              : {
                  cleanup: {
                    reason: "native stop unconfirmed",
                    resources: ["owned native fixture worker"],
                  },
                }),
          },
        );
        if (state === "pending" || state === "resolved")
          failure.bindCleanupResourceOwner({
            get cleanupResources() {
              return resources;
            },
          });
        if (state === "resolved") failure.resolveCleanup();
        options.onFailure?.(failure);
        return err(failure);
      }
      const result = await graph.port.execute(operation, input, execution);
      if (!result.ok) return result;
      const observed = createAnalysisExecution(
        result.value.result,
        nativeCleanupIdentity,
        {
          subject,
          rawResult: result.value.rawResult,
          limitations: result.value.limitations,
          ...(profile === undefined ? {} : { analysisProfile: profile }),
        },
      );
      if (operation === "analyze_function" && selector === "0x1000")
        partial = createAnalysisExecutionEvidence(
          operation,
          input,
          observed,
          "observed",
        );
      return ok(observed);
    },
  });
  const provider = (
    closed: string[] = [],
    onClose?: () => void,
  ): AnalysisProvider => ({
    identity: () => nativeCleanupIdentity,
    capabilities,
    createClient: (target, profile) => {
      const port = portFor(target, profile);
      return {
        execute: (operation, input, execution) =>
          operation === "health"
            ? Promise.resolve(
                ok(createAnalysisExecution(null, nativeCleanupIdentity)),
              )
            : port.execute(operation, input, execution),
        close: async () => {
          onClose?.();
          if (failure?.cleanupIncomplete === true && !proofAvailable)
            return err(failure);
          resources = [];
          failure?.resolveCleanup();
          closed.push(target.path);
          return ok(null);
        },
      };
    },
  });
  return {
    port: portFor(valueTraceSubject),
    provider,
    calls,
    cause,
    failure: () => failure,
    partial: () => partial,
    proveCleanup: () => {
      proofAvailable = true;
    },
  };
};
