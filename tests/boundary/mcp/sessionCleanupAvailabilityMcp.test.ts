import { expect, it } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { err, ok } from "../../../src/domain/result.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import {
  createBinarySessionTargets,
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";

it.each(["full", "compact"] as const)(
  "preserves the known close prerequisite in the %s session schema",
  async (profile) => {
    const [target] = await createBinarySessionTargets();
    const reads: string[] = [];
    const provider = createCacheProvider(reads);
    const failure = new ProviderCleanupError(
      "fixture",
      ["owned fixture resource"],
      {},
    );
    let pending = true;
    const session = createTestBinarySession({
      ...provider,
      createClient: (...args) => ({
        ...provider.createClient(...args),
        close: async () => (pending ? err(failure) : ok(null)),
      }),
    });
    const harness = await createApplicationMcpHarness({
      session,
      serverOptions: {
        environment: {
          REA_MCP_OUTPUT_SCHEMA_PROFILE: profile,
          REA_MCP_TOOL_FAMILIES: "session,direct",
        },
      },
    });
    try {
      const statusSchema = await advertisedMcpToolSchemas(
        harness.client,
        "binary_session",
      );
      const closeSchema = await advertisedMcpToolSchemas(
        harness.client,
        "close_binary",
      );
      expect((await session.open(target)).ok).toBe(true);
      expect(
        (
          await session.execute("address_name", {
            address: "0x1000",
            document: "fixture",
          })
        ).ok,
      ).toBe(true);
      const originalReads = [...reads];
      const close = () =>
        harness.client.callTool(
          { name: "close_binary", arguments: {} },
          { toolDefinition: closeSchema.toolDefinition },
        );
      const failed = parseMcpToolError(await close());
      expect(failed.error).toMatchObject({
        code: "cleanup_incomplete",
        recovery: { kind: "retry_cleanup", operation: "close_binary" },
      });
      const originalWire = JSON.stringify(failed);
      const status = async (detail: "summary" | "complete") => {
        const reply = await harness.client.callTool(
          { name: "binary_session", arguments: { detail } },
          { toolDefinition: statusSchema.toolDefinition },
        );
        expect(reply.isError, JSON.stringify(reply.content)).not.toBe(true);
        expect(
          statusSchema.ajv.validate(
            statusSchema.outputSchema,
            reply.structuredContent,
          ),
          JSON.stringify(statusSchema.ajv.errors),
        ).toBe(true);
        return toolContract("binary_session").outputSchema.parse(
          reply.structuredContent,
        ).result;
      };
      for (const detail of ["summary", "complete"] as const) {
        const blocked = await status(detail);
        expect(blocked).toMatchObject({
          open: false,
          cleanup_pending: true,
          cleanup_retry: { operation: "close_binary" },
        });
        const entry = expandToolAvailability(blocked.tool_availability).find(
          ({ name }) => name === "procedure_assembly",
        );
        expect(entry?.remediation).toContain("close_binary");
        expect(entry?.remediation).toContain(
          "without rerunning the failed analysis",
        );
      }
      // A still-unresolved retry retains the same prerequisite.
      expect(parseMcpToolError(await close()).error.code).toBe(
        "cleanup_incomplete",
      );
      pending = false;
      expect((await close()).isError).not.toBe(true);
      for (const detail of ["summary", "complete"] as const) {
        const settled = await status(detail);
        expect(settled).toMatchObject({ open: false, cleanup_pending: false });
        expect(settled).not.toHaveProperty("cleanup_retry");
        expect(
          expandToolAvailability(settled.tool_availability).find(
            ({ name }) => name === "procedure_assembly",
          )?.remediation,
        ).toBe("Call open_binary with a supported local target.");
      }
      expect(reads).toEqual(originalReads);
      expect(failure.cleanupIncomplete).toBe(false);
      expect(JSON.stringify(failed)).toBe(originalWire);
    } finally {
      pending = false;
      await harness.close();
    }
  },
);
