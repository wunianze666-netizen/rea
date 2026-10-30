import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { browserScenarioDiffSchema } from "../../../src/domain/browserScenarioDiffValues.js";
import type { BrowserScenarioCapture } from "../../../src/domain/browserScenarioCapture.js";
import { classifyBrowserScenarioCompleteness } from "../../../src/domain/browserScenarioCaptureValues.js";
import { failedRequestScenario } from "../../fixtures/failedRequestScenario.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "compares retained request-failure outcomes while preserving real content gaps through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-failed-request-coverage-");
    const call =
      surface === "stdio MCP"
        ? (await connectLocalToolsMcp({ REA_MCP_MAX_INPUT_ELEMENTS: "8192" }))
            .call
        : undefined;
    const compare = async (
      before: BrowserScenarioCapture,
      after: BrowserScenarioCapture,
    ) => {
      let evidence: unknown;
      if (call === undefined) {
        const beforePath = join(root, "before.json");
        const afterPath = join(root, "after.json");
        await Promise.all([
          writeFile(beforePath, JSON.stringify(before)),
          writeFile(afterPath, JSON.stringify(after)),
        ]);
        const output = await cli.run({
          arguments: ["compare-web-captures", beforePath, afterPath, "--json"],
        });
        expect(output.exitCode, output.stderr).toBe(0);
        evidence = output.json;
      } else {
        const output = await call("compare_web_captures", {
          before_scenario: before,
          after_scenario: after,
        });
        expect(output.isError, JSON.stringify(output)).not.toBe(true);
        evidence = output.structuredContent;
      }
      return browserScenarioDiffSchema.parse(
        parseEvidence(evidence).normalized_result,
      );
    };
    const before = await failedRequestScenario("one");
    const equal = await failedRequestScenario("one");
    const changed = await failedRequestScenario("two");
    expect(before.failedBodyReads).toBe(0);
    expect(before.capture.events.dropped).toBe(0);
    expect(before.capture.events.items).toContainEqual(
      expect.objectContaining({
        kind: "request-failed",
        failure: "net::ERR_ABORTED",
      }),
    );
    expect(before.capture.events.items).toContainEqual(
      expect.objectContaining({
        kind: "network-content",
        body: expect.objectContaining({
          state: "unavailable",
          reason: "request-failed",
        }),
      }),
    );
    expect((await compare(before.capture, equal.capture)).overall_status).toBe(
      "unchanged",
    );
    const difference = await compare(before.capture, changed.capture);
    expect(difference.overall_status).toBe("changed");
    expect(
      difference.steps.flatMap(({ artifact_diffs }) => artifact_diffs),
    ).toContainEqual(
      expect.objectContaining({ artifact: "events", status: "changed" }),
    );
    for (const fault of ["body", "headers"] as const) {
      const missing = await failedRequestScenario("one", fault);
      expect(missing.capture.completeness).toMatchObject({
        status: "incomplete",
        equality_eligible: false,
        missing_sections: ["events"],
      });
      expect(
        (await compare(missing.capture, missing.capture)).overall_status,
      ).toBe("unknown");
    }
    const legacy = {
      ...before.capture,
      completeness: classifyBrowserScenarioCompleteness(["events"], []),
    };
    expect((await compare(legacy, legacy)).overall_status).toBe("unknown");
  },
);
