import { expect, it } from "vitest";
import { compareFunctions } from "./functionComparison.js";
import { functionSnapshotFixture } from "./functionDossierEvidence.fixture.js";
import {
  functionSnapshotCoordinateContext,
  parseFunctionEvidence,
} from "./functionDossierEvidence.js";
import { functionSelfComparisonFixture } from "../../tests/fixtures/functionSelfComparison.js";
import { parseEvidence } from "./evidence.js";
import { functionDossierSchema } from "./native/functionDossier.js";
import { functionComparisonResultSchema } from "./functionComparisonSchemas.js";

it.each([false, true])(
  "identical authenticated observations correspond with nonsemantic metadata changed=%s",
  (differentMetadata) => {
    const source = functionSelfComparisonFixture();
    const right = parseEvidence(
      differentMetadata
        ? { ...source, caller_input_path: "/another/request/path" }
        : structuredClone(source),
    );
    const leftSnapshot = functionSnapshotFixture(source);
    const rightSnapshot = functionSnapshotFixture(right);
    expect(right.evidence_id).toBe(source.evidence_id);
    expect(functionSnapshotCoordinateContext(leftSnapshot, rightSnapshot)).toBe(
      "unknown",
    );
    const result = compareFunctions(leftSnapshot, rightSnapshot);
    expect(result.function_match).toMatchObject({
      status: "matched",
      method: "same-evidence",
      evidence_id: source.evidence_id,
    });
    expect(
      result.dimensions.find(({ dimension }) => dimension === "identity"),
    ).toMatchObject({ status: "unchanged" });
    expect(
      result.dimensions.find(({ dimension }) => dimension === "calls"),
    ).toMatchObject({ status: "unknown" });
    expect(result.status).toBe("unknown");
    expect(source.normalized_result).toEqual(right.normalized_result);
    expect(leftSnapshot.dossier.procedure.symbol).toBeNull();
  },
);

it.each(["selection", "caveat"] as const)(
  "equal-looking dossiers with distinct %s commitments remain ambiguous",
  (changed) => {
    const left = functionSelfComparisonFixture();
    const right = functionSelfComparisonFixture(
      changed === "selection" ? "another-selection" : "selected",
      changed === "caveat" ? "Another caveat." : "Fixture provenance.",
    );
    expect(left.normalized_result).toEqual(right.normalized_result);
    expect(left.evidence_id).not.toBe(right.evidence_id);
    const result = compareFunctions(
      functionSnapshotFixture(left),
      functionSnapshotFixture(right),
    );
    expect(result.function_match).toMatchObject({
      status: "ambiguous",
      method: "explicit",
    });
    expect(
      result.dimensions.find(({ dimension }) => dimension === "identity"),
    ).toMatchObject({ status: "unknown" });
  },
);

it("rejects a tampered record carrying the selected Evidence ID", () => {
  const source = functionSelfComparisonFixture();
  const changed = functionDossierSchema.parse(source.normalized_result);
  changed.procedure.name = "tampered";
  const result = parseFunctionEvidence(
    { ...source, normalized_result: changed },
    { operation: "compare_functions", path: ["right"] },
  );
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("Expected Evidence authentication failure");
  expect(result.error._tag).toBe("EvidenceIntegrityError");
});

it.each(["id", "subject", "name"] as const)(
  "rejects a contradictory same-Evidence %s claim",
  (changed) => {
    const source = functionSnapshotFixture(functionSelfComparisonFixture());
    const result = compareFunctions(source, source);
    const altered = structuredClone(result);
    if (altered.function_match.method !== "same-evidence")
      throw new Error("Expected same-Evidence correspondence");
    if (changed === "id")
      altered.function_match.evidence_id = `ev_${"b".repeat(64)}`;
    if (changed === "subject") altered.right_subject_sha256 = "b".repeat(64);
    if (changed === "name")
      altered.function_match.right_name = "another observation";
    expect(functionComparisonResultSchema.safeParse(altered).success).toBe(
      false,
    );
  },
);
