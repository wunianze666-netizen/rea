import {
  createAnalysisExecution,
  type AnalysisProvider,
  type CapabilityDescriptor,
} from "../../src/application/AnalysisProvider.js";
import { AnalysisCapabilityUnavailableError } from "../../src/domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../src/domain/evidence.js";
import { err, ok } from "../../src/domain/result.js";

const callCleanupProviderIdentity = {
  id: "fixture",
  name: "Fixture analysis provider",
  version: "1",
};

/** Real session seam with an explicitly owned, simulated cleanup obligation. No process is launched. */
export const callTraversalCleanupFixture = (
  direction: "forward" | "backward",
  pending = true,
) => {
  const operation =
    direction === "forward" ? "procedure_callees" : "procedure_callers";
  const reads: string[] = [];
  let proofAvailable = !pending;
  let resources: string[] = [];
  let failure: AnalysisCapabilityUnavailableError | undefined;
  let partial: Evidence | undefined;
  let closeAttempts = 0;
  const provider = (closed: string[] = []): AnalysisProvider => ({
    identity: () => callCleanupProviderIdentity,
    capabilities: () =>
      (
        ["procedure_address", "procedure_callees", "procedure_callers"] as const
      ).map((name): CapabilityDescriptor => ({
        provider: callCleanupProviderIdentity,
        operation: name,
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
      })),
    createClient: (target, analysisProfile) => ({
      execute: async (name, parameters) => {
        const address = String(parameters.procedure);
        const observe = (value: unknown) =>
          ok(
            createAnalysisExecution(value, callCleanupProviderIdentity, {
              subject: target,
              ...(analysisProfile === undefined ? {} : { analysisProfile }),
              ...(name === operation
                ? { relationshipCoverage: { status: "complete" as const } }
                : {}),
            }),
          );
        if (name === "health") return observe(null);
        if (name === "procedure_address") return observe(address);
        if (name !== operation)
          throw new Error(`Unexpected provider operation ${name}`);
        reads.push(address);
        if (address !== "0x2")
          return observe(
            address === "0x1"
              ? ["0x2", "0x3"]
              : address === "0x3"
                ? ["0x4"]
                : [],
          );
        partial ??= createEvidence(target, callCleanupProviderIdentity, {
          operation,
          parameters: { procedure: address },
          result: [],
          relationshipCoverage: {
            status: "partial",
            limitations: ["Synthetic partial relationship read."],
          },
          ...(analysisProfile === undefined ? {} : { analysisProfile }),
        });
        if (failure === undefined) {
          resources = pending ? ["owned synthetic relationship worker"] : [];
          failure = new AnalysisCapabilityUnavailableError(
            callCleanupProviderIdentity.id,
            operation,
            "synthetic child failure",
            {
              partialObservation: partial,
              ...(pending
                ? { cleanup: { reason: "stop is unconfirmed", resources } }
                : {}),
            },
          );
          if (pending)
            failure.bindCleanupResourceOwner({
              get cleanupResources() {
                return resources;
              },
            });
        }
        return err(failure);
      },
      close: async () => {
        closeAttempts++;
        if (failure?.cleanupIncomplete === true && !proofAvailable)
          return err(failure);
        resources = [];
        failure?.resolveCleanup();
        closed.push(target.path);
        return ok(null);
      },
    }),
  });
  return {
    provider,
    reads,
    proveCleanup: () => {
      proofAvailable = true;
    },
    failure: () => failure,
    partial: () => partial,
    closeAttempts: () => closeAttempts,
  };
};
