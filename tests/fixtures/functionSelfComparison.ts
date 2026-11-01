import { FUNCTION_COMPARISON_EXAMPLE } from "../../src/contracts/functionComparisonExample.js";
import { createAnalysisProfile } from "../../src/domain/analysisProfile.js";
import { createEvidence } from "../../src/domain/evidence.js";
import { functionDossierSchema } from "../../src/domain/native/functionDossier.js";

/** Authored retained metadata, not a live Kuna/Ghidra capture or a coordinate commitment. */
export const functionSelfComparisonFixture = (
  selection = "selected",
  caveat = "Fixture provenance.",
) => {
  const base = FUNCTION_COMPARISON_EXAMPLE.left;
  const dossier = functionDossierSchema.parse(base.normalized_result);
  dossier.procedure.symbol = null;
  dossier.procedure.name = "fixture_entry";
  delete dossier.facet_availability;
  const provider = {
    id: "kuna",
    name: "Authored Kuna metadata fixture",
    version: "1.986",
  };
  return createEvidence(
    {
      path: "/fixture/self-comparison",
      sha256: "a".repeat(64),
      format: "mach-o",
      architecture: "arm64",
    },
    provider,
    {
      operation: "analyze_function",
      parameters: { procedure: selection },
      result: dossier,
      analysisProfile: createAnalysisProfile(provider, { fixture: true }),
      limitations: [caveat],
      confidence: "observed",
    },
  );
};
