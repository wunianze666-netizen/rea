import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
import { buildCapabilityInventory } from "../../../src/application/CapabilityInventory.js";
import { providerCapabilitySets } from "../../../src/application/binary/BinarySessionStatus.js";
import { JebProvider } from "../../../src/jeb/JebProvider.js";
import { JebMcpDeadline } from "../../../src/jeb/JebMcpDeadline.js";
import { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import {
  AdbConfigurationFailure,
  adbConfigurationAvailability,
} from "../../../src/adb/AdbConfiguration.js";
import {
  ApktoolConfigurationFailure,
  apktoolConfigurationAvailability,
} from "../../../src/apktool/ApktoolConfiguration.js";
import { IdaProvider } from "../../../src/ida/IdaProvider.js";
import { idaCapabilities } from "../../../src/ida/IdaProviderCapabilities.js";
import { IDA_COMPATIBILITY_PROFILES } from "../../../src/ida/IdaConfiguration.js";
import {
  expandProviderCapabilities,
  providerCapabilitySet,
} from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const idle = { open: false, capabilities: [] };
const policy = { processCaptureEnabled: false };

const deadlineFailure = async (signal?: AbortSignal) => {
  const deadline = new JebMcpDeadline(1, signal, "discovery");
  try {
    if (!deadline.signal.aborted)
      await new Promise<void>((resolve) =>
        deadline.signal.addEventListener("abort", () => resolve(), {
          once: true,
        }),
      );
    const error = deadline.failure("jeb_mcp_catalog", deadline.signal.reason);
    if (!(error instanceof AnalysisError))
      throw new Error("Expected typed deadline failure");
    return error;
  } finally {
    deadline.dispose();
  }
};

const failedJeb = (failure: AnalysisError) =>
  new JebProvider({
    connectionFactory: () => ({
      async connect() {
        throw failure;
      },
      async listTools() {
        throw failure;
      },
      async call() {
        throw failure;
      },
      async close() {},
    }),
  });

it("keeps the real JEB deadline's recovery through discovery and inventory", async () => {
  const failure = await deadlineFailure();
  const expected = projectAnalysisError(failure);
  const provider = failedJeb(failure);
  onTestFinished(() => provider.close());
  const observation = await provider.inspectAvailability();
  expect(observation).toMatchObject({
    status: "unavailable",
    code: "runtime_unavailable",
    reason: expected.message,
  });
  const entry = buildCapabilityInventory(idle, {
    ...policy,
    jebAnalysisAvailability: observation,
  }).find(({ name }) => name === "inspect_jeb_client");
  expect(entry?.remediation).toBe(expected.remediation.action);
  expect(observation.diagnostics.failure).toEqual({
    code: expected.code,
    category: expected.category,
    timeout_ms: 1,
  });
});

it("keeps ordinary JEB connection advice separate from its failure description", async () => {
  const provider = new JebProvider({
    connectionFactory: () => ({
      async connect() {
        throw new Error("controlled offline");
      },
      async listTools() {
        throw new Error("controlled offline");
      },
      async call() {
        throw new Error("No call expected");
      },
      async close() {},
    }),
  });
  onTestFinished(() => provider.close());
  const observation = await provider.inspectAvailability();
  const entry = buildCapabilityInventory(idle, {
    ...policy,
    jebAnalysisAvailability: observation,
  }).find(({ name }) => name === "inspect_jeb_client");
  expect(entry?.remediation).toContain("REA_JEB_MCP_URL");
  expect(entry?.remediation).not.toContain("controlled offline");
  expect(observation.reason).toContain("controlled offline");
});

it("does not coalesce distinct producer recovery actions and preserves them through wire expansion", () => {
  const declared = idaCapabilities(IDA_COMPATIBILITY_PROFILES.modern, false)[0];
  if (declared === undefined)
    throw new Error("Expected a declared IDA capability");
  const failure = {
    ...declared,
    available: false as const,
    availabilityCode: "not_configured" as const,
    reason: "Controlled refusal",
  };
  const sets = providerCapabilitySets([
    {
      ...failure,
      operation: "procedure_pseudo_code",
      remediation: "first owned repair",
    },
    {
      ...failure,
      operation: "procedure_assembly",
      remediation: "second owned repair",
    },
  ]).map((set) => providerCapabilitySet.parse(set));
  expect(sets[0]?.groups).toHaveLength(2);
  expect(
    expandProviderCapabilities(sets).map((capability) =>
      capability.available ? null : capability.remediation,
    ),
  ).toEqual(["first owned repair", "second owned repair"]);
});

it.each(["adb", "apktool"] as const)(
  "keeps %s configuration-owner advice in the final capability",
  (kind) => {
    const remediation = `Owned ${kind} execute-permission repair advice`;
    const observation =
      kind === "adb"
        ? adbConfigurationAvailability(
            new AdbConfigurationFailure(
              "binary_not_executable",
              "Controlled execution refusal",
              { remediation },
            ),
          )
        : apktoolConfigurationAvailability(
            new ApktoolConfigurationFailure(
              "command_not_executable",
              "Controlled execution refusal",
              { remediation },
            ),
          );
    const inventory = buildCapabilityInventory(idle, {
      ...policy,
      ...(kind === "adb"
        ? { adbAnalysisAvailability: observation }
        : { apktoolAnalysisAvailability: observation }),
    });
    expect(
      inventory.find(({ name }) => name === `inspect_${kind}_client`)
        ?.remediation,
    ).toBe(remediation);
    expect(observation.reason).toBe("Controlled execution refusal");
  },
);

it("carries IDA's real missing-registration recovery through capability grouping", async () => {
  const root = await createTestTempDirectory("rea-ida-recovery-");
  const config = parseConfig({
    REA_IDA_MCP_CONFIG: join(root, "missing.json"),
  });
  if (!config.ok) throw config.error;
  let connections = 0;
  const provider = new IdaProvider(config.value, {}, () => {
    connections++;
    throw new Error("No IDA connection expected");
  });
  onTestFinished(async () => {
    expect((await provider.closeOwnedResources()).ok).toBe(true);
  });
  const readiness = await provider.inspectReadinessSnapshot();
  const expected = readiness.availability.diagnostics.configuration_remediation;
  if (typeof expected !== "string")
    throw new Error("Expected producer-owned configuration recovery");
  const inventory = buildCapabilityInventory(
    {
      open: true,
      kind: "executable",
      capabilities: providerCapabilitySets(readiness.capabilities),
    },
    policy,
  );
  expect(
    inventory.find(({ name }) => name === "analyze_function")?.remediation,
  ).toBe(expected);
  expect(connections).toBe(0);
});

it("preserves a legacy reason when no actionable recovery was supplied", () => {
  const entry = buildCapabilityInventory(idle, {
    ...policy,
    adbAnalysisAvailability: {
      status: "unavailable",
      code: "not_configured",
      reason: "Legacy readiness reason",
      diagnostics: {},
    },
  }).find(({ name }) => name === "inspect_adb_client");
  expect(entry?.remediation).toBe("Legacy readiness reason");
});

it("does not turn stale diagnostic advice into a successful probe failure", () => {
  const entry = buildCapabilityInventory(idle, {
    ...policy,
    adbAnalysisAvailability: {
      status: "available",
      code: null,
      reason: null,
      diagnostics: { remediation: "Old advice" },
    },
  }).find(({ name }) => name === "inspect_adb_client");
  expect(entry).toMatchObject({ available: true, remediation: null });
});

it("keeps caller cancellation as the original failure", async () => {
  const controller = new AbortController();
  controller.abort("caller cancellation");
  const failure = await deadlineFailure(controller.signal);
  const provider = failedJeb(failure);
  onTestFinished(() => provider.close());
  await expect(provider.inspectAvailability(controller.signal)).rejects.toBe(
    failure,
  );
  expect(projectAnalysisError(failure).code).toBe("cancelled");
});
