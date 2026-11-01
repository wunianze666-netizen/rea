import { join } from "node:path";
import { expect } from "vitest";
import { z } from "zod";
import {
  analysisProviderCandidate,
  expandProviderCapabilities,
} from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for(["providers", "capabilities"] as const)(
  "%s preserves IDA configuration-owner recovery",
  async (command, { cli }) => {
    const root = await createTestTempDirectory("rea-recovery-cli-");
    const output = await cli.run({
      arguments: [command, "--format", "json"],
      environment: {
        REA_IDA_MCP_CONFIG: join(root, "missing-ida.json"),
        HOPPER_LAUNCHER_PATH: join(root, "missing-hopper"),
        GHIDRA_INSTALL_DIR: process.execPath,
        REA_LOG_LEVEL: "silent",
      },
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const status = z
      .object({
        analysis_provider_candidates: analysisProviderCandidate.array(),
      })
      .parse(output.json);
    const ida = status.analysis_provider_candidates.find(
      ({ provider }) => provider.id === "ida",
    );
    if (ida === undefined || ida.availability.status !== "unavailable")
      throw new Error("Expected unavailable IDA configuration");
    const recovery = ida.availability.diagnostics.configuration_remediation;
    expect(typeof recovery).toBe("string");
    expect(ida.availability.remediation).toBe(recovery);
    expect(ida.availability.remediation).not.toBe(ida.availability.reason);
    expect(
      expandProviderCapabilities(ida.capabilities).find(
        ({ operation }) => operation === "procedure_pseudo_code",
      ),
    ).toMatchObject({ available: false, remediation: recovery });
  },
);
