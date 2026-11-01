import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
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
import { parseConfig } from "../../../src/config/parseConfig.js";
import { BinarySession } from "../../../src/application/binary/BinarySession.js";
import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { SessionProviderRouter } from "../../../src/application/binary/SessionProviderRouter.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
  expandToolAvailability,
  expandProviderCapabilities,
  providerCapabilitySet,
} from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it.each(["full", "compact"] as const)(
  "delivers provider-owned recovery through the %s session schema",
  async (profile) => {
    const deadline = new JebMcpDeadline(1, undefined, "discovery");
    onTestFinished(() => deadline.dispose());
    if (!deadline.signal.aborted)
      await new Promise<void>((resolve) =>
        deadline.signal.addEventListener("abort", () => resolve(), {
          once: true,
        }),
      );
    const failure = deadline.failure("jeb_mcp_catalog", deadline.signal.reason);
    if (!(failure instanceof AnalysisError))
      throw new Error("Expected deadline-owned failure");
    const jebAction = projectAnalysisError(failure).remediation.action;
    let executionCalls = 0;
    const jeb = new JebProvider({
      connectionFactory: () => ({
        async connect() {
          throw failure;
        },
        async listTools() {
          throw failure;
        },
        async call() {
          executionCalls++;
          throw new Error("No engine operation expected");
        },
        async close() {},
      }),
    });
    const adbAction = "Repair the selected ADB execute permissions";
    const apktoolAction = "Repair the selected Apktool execute permissions";
    const adb = adbConfigurationAvailability(
      new AdbConfigurationFailure(
        "binary_not_executable",
        "Controlled refusal",
        { remediation: adbAction },
      ),
    );
    const apktool = apktoolConfigurationAvailability(
      new ApktoolConfigurationFailure(
        "command_not_executable",
        "Controlled refusal",
        { remediation: apktoolAction },
      ),
    );
    const root = await createTestTempDirectory("rea-provider-recovery-mcp-");
    const config = parseConfig({
      REA_IDA_MCP_CONFIG: join(root, "missing.json"),
    });
    if (!config.ok) throw config.error;
    let idaConnections = 0;
    const ida = new IdaProvider(config.value, {}, () => {
      idaConnections++;
      throw new Error("No IDA connection expected");
    });
    onTestFinished(async () => {
      expect((await ida.closeOwnedResources()).ok).toBe(true);
    });
    const readiness = await ida.inspectReadinessSnapshot();
    const idaAction =
      readiness.availability.diagnostics.configuration_remediation;
    if (typeof idaAction !== "string")
      throw new Error("Expected IDA-owned recovery");
    const session = new BinarySession(
      SessionProviderRouter.selectable(new AnalysisProviderRegistry([ida]), []),
    );
    const { client } = await createApplicationMcpHarness({
      session,
      serverOptions: {
        environment: {
          REA_MCP_OUTPUT_SCHEMA_PROFILE: profile,
          REA_MCP_TOOL_FAMILIES: "session,direct,enhanced,jeb,adb,apktool",
        },
        jebAnalysis: jeb,
        adbDeviceAnalysis: {
          async inspectAvailability() {
            return adb;
          },
          async execute() {
            executionCalls++;
            throw new Error("No ADB request expected");
          },
          async close() {},
        },
        apktoolAnalysis: {
          async inspectAvailability() {
            return apktool;
          },
          async execute() {
            executionCalls++;
            throw new Error("No Apktool request expected");
          },
          async close() {},
        },
      },
    });
    const schemas = await advertisedMcpToolSchemas(client, "binary_session");
    for (const detail of ["summary", "complete"] as const) {
      const reply = await client.callTool(
        { name: "binary_session", arguments: { detail } },
        { toolDefinition: schemas.toolDefinition },
      );
      expect(reply.isError, JSON.stringify(reply.content)).not.toBe(true);
      expect(
        schemas.ajv.validate(schemas.outputSchema, reply.structuredContent),
        JSON.stringify(schemas.ajv.errors),
      ).toBe(true);
      const status = toolContract("binary_session").outputSchema.parse(
        reply.structuredContent,
      ).result;
      const inventory = expandToolAvailability(status.tool_availability);
      for (const [name, remediation] of [
        ["inspect_jeb_client", jebAction],
        ["inspect_adb_client", adbAction],
        ["inspect_apktool_client", apktoolAction],
      ])
        expect(inventory.find((item) => item.name === name)).toMatchObject({
          available: false,
          remediation,
        });
      const candidate = status.analysis_provider_candidates.find(
        ({ provider }) => provider.id === "ida",
      );
      expect(candidate?.availability).toMatchObject({
        status: "unavailable",
        remediation: idaAction,
      });
      if (candidate !== undefined && "capabilities" in candidate) {
        const capabilities = expandProviderCapabilities(
          providerCapabilitySet.array().parse(candidate.capabilities),
        );
        expect(
          capabilities.find(
            ({ operation }) => operation === "procedure_pseudo_code",
          ),
        ).toMatchObject({ available: false, remediation: idaAction });
      }
    }
    expect(executionCalls).toBe(0);
    expect(idaConnections).toBe(0);
  },
);
