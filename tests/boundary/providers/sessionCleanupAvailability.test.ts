import { expect, it } from "vitest";
import { buildCapabilityInventory } from "../../../src/application/CapabilityInventory.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { err, ok } from "../../../src/domain/result.js";
import {
  createBinarySessionTargets,
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";

it("offers the retained close prerequisite before opening another target", async () => {
  const [target] = await createBinarySessionTargets();
  const calls: string[] = [];
  const provider = createCacheProvider(calls);
  let pending = true;
  const failure = new ProviderCleanupError(
    "fixture",
    ["owned fixture resource"],
    {},
  );
  const session = createTestBinarySession({
    ...provider,
    createClient: (...args) => ({
      ...provider.createClient(...args),
      close: async () => (pending ? err(failure) : ok(null)),
    }),
  });
  try {
    expect((await session.open(target)).ok).toBe(true);
    expect(
      (
        await session.execute("address_name", {
          address: "0x1000",
          document: "fixture",
        })
      ).ok,
    ).toBe(true);
    const closed = await session.close({
      cleanupRetry: { operation: "close_binary" },
    });
    expect(closed.ok).toBe(false);
    expect(failure.cleanupIncomplete).toBe(true);
    const historicalFailure = JSON.stringify(projectAnalysisError(failure));
    const reads = [...calls];
    const status = await session.status();
    expect(status).toMatchObject({
      open: false,
      cleanup_pending: true,
      cleanup_retry: { operation: "close_binary" },
    });
    const availability = buildCapabilityInventory(status, {
      processCaptureEnabled: true,
    });
    expect(
      availability.find(({ name }) => name === "procedure_assembly")
        ?.remediation,
    ).toContain("close_binary");
    expect((await session.open(target)).ok).toBe(false);
    pending = false;
    expect((await session.close()).ok).toBe(true);
    const settled = await session.status();
    expect(settled).toMatchObject({ open: false, cleanup_pending: false });
    expect(settled).not.toHaveProperty("cleanup_retry");
    expect(
      buildCapabilityInventory(settled, { processCaptureEnabled: true }).find(
        ({ name }) => name === "procedure_assembly",
      )?.remediation,
    ).toBe("Call open_binary with a supported local target.");
    expect(calls).toEqual(reads);
    expect(JSON.parse(historicalFailure).code).toBe("cleanup_incomplete");
    expect(failure.cleanupIncomplete).toBe(false);
  } finally {
    pending = false;
    const closed = await session.close();
    if (!closed.ok) throw closed.error;
  }
});

it.each(["external", "mixed"] as const)(
  "does not assign a close retry to %s external-mutation cleanup",
  async (kind) => {
    const provider = createCacheProvider([]);
    let pending = kind === "mixed";
    const external = new ProviderCleanupError(
      "external-fixture",
      ["external resource"],
      {},
      { operation: "execute_rizin_command" },
    );
    const closeFailure = new ProviderCleanupError(
      "fixture",
      ["client resource"],
      {},
    );
    const session = createTestBinarySession({
      ...provider,
      createClient: (...args) => ({
        ...provider.createClient(...args),
        close: async () => (pending ? err(closeFailure) : ok(null)),
      }),
    });
    try {
      if (kind === "mixed") {
        const [target] = await createBinarySessionTargets();
        expect((await session.open(target)).ok).toBe(true);
        expect(
          (
            await session.execute("address_name", {
              address: "0x1000",
              document: "fixture",
            })
          ).ok,
        ).toBe(true);
      }
      // A controlled owner returns its cleanup obligation; no external command runs.
      await session.withAdmittedExternalMutation(
        undefined,
        undefined,
        async () => err(external),
        (_value, failure) => failure,
      );
      const status = await session.status();
      expect(status).toMatchObject({ open: false, cleanup_pending: true });
      expect(status).not.toHaveProperty("cleanup_retry");
      const advice = buildCapabilityInventory(status, {
        processCaptureEnabled: true,
      }).find(({ name }) => name === "procedure_assembly")?.remediation;
      expect(advice).toContain("owning failure");
      expect(advice).not.toContain("close_binary");
      expect(external.cleanupIncomplete).toBe(true);
    } finally {
      pending = false;
      external.resolveCleanup();
      const closed = await session.close();
      if (!closed.ok) throw closed.error;
    }
  },
);

it("keeps legacy no-target guidance and never infers a retry from a pending flag", () => {
  const advice = (status: Parameters<typeof buildCapabilityInventory>[0]) =>
    buildCapabilityInventory(status, { processCaptureEnabled: true }).find(
      ({ name }) => name === "procedure_assembly",
    )?.remediation;
  expect(advice({ open: false, capabilities: [] })).toBe(
    "Call open_binary with a supported local target.",
  );
  expect(
    advice({ open: false, capabilities: [], cleanup_pending: true }),
  ).not.toContain("close_binary");
  expect(
    advice({
      open: false,
      capabilities: [],
      cleanup_pending: false,
      cleanup_retry: { operation: "close_binary" },
    }),
  ).toBe("Call open_binary with a supported local target.");
});
