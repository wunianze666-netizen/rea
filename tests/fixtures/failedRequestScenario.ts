import { AnalysisCleanupLease } from "../../src/artifacts/AnalysisCleanupLease.js";
import { browserScenarioSchema } from "../../src/domain/browserScenario.js";
import { sanitizeBrowserUrl } from "../../src/domain/browserObservation.js";
import {
  browserScenarioEventSchema,
  browserStepArtifactsSchema,
  type BrowserScenarioEvent,
} from "../../src/domain/browserScenarioCaptureValues.js";
import { PlaywrightBrowserScenarioProvider } from "../../src/browser/PlaywrightBrowserScenarioProvider.js";
import type { BrowserScenarioSessionPort } from "../../src/browser/BrowserScenarioSessionPort.js";
import {
  PlaywrightScenarioNetwork,
  type ScenarioNetworkRequest,
  type ScenarioNetworkResponse,
} from "../../src/browser/network/PlaywrightScenarioNetwork.js";
import { resolveScenarioSecrets } from "./browserScenarioSecrets.js";

const origin = "https://example.test";
type Fault = "body" | "headers" | undefined;

const requestFor = (path: string): ScenarioNetworkRequest => ({
  method: () => "GET",
  url: () => `${origin}${path}`,
  resourceType: () => (path.endsWith(".js") ? "script" : "fetch"),
  headers: () => ({}),
  headersArray: async () => [],
  postDataBuffer: () => null,
  redirectedFrom: () => null,
  failure: () => ({ errorText: "net::ERR_ABORTED" }),
});

const responseFor = (
  request: ScenarioNetworkRequest,
  status: number,
  text: string,
  fault?: Fault,
) => {
  let bodyReads = 0;
  const source: ScenarioNetworkResponse = {
    request: () => request,
    url: () => request.url(),
    status: () => status,
    headers: () => ({ "content-type": "application/json" }),
    headersArray: async () => {
      if (fault === "headers") throw new Error("authored header read failure");
      return [{ name: "Content-Type", value: "application/json" }];
    },
    body: async () => {
      bodyReads += 1;
      if (fault === "body") throw new Error("authored body read failure");
      return Buffer.from(text);
    },
  };
  return { source, bodyReads: () => bodyReads };
};

/** Real capture/network owners with an injected session; no browser or destination request is executed. */
export const failedRequestScenario = async (value: string, fault?: Fault) => {
  const scenario = browserScenarioSchema.parse({
    browser: { mode: "launch", executable_path: "/fixture/no-browser" },
    start_url: { url: origin },
    actions: [
      { step_id: "network", action: "wait_for_timeout", duration_ms: 1 },
    ],
    capture: {
      events: ["network"],
      network: { response_body: true, header_values: fault === "headers" },
      after_each_step: [],
      at_end: [],
    },
  });
  const events: BrowserScenarioEvent[] = [];
  let step = 0;
  const unexpectedOmission = (): never => {
    throw new Error("Tiny fixture unexpectedly exceeded an admission budget");
  };
  const network = new PlaywrightScenarioNetwork({
    selection: scenario.capture.network,
    limits: scenario.capture.limits,
    secrets: resolveScenarioSecrets(scenario, {}),
    emit: (event) => {
      const sequence = events.length + 1;
      events.push(
        browserScenarioEventSchema.parse({
          ...event,
          sequence,
          step_index: step,
        }),
      );
      return { status: "retained", sequence };
    },
    admitText: () => ({ status: "retained", sequence: events.length + 1 }),
    admitContentBody: () => ({
      status: "retained",
      sequence: events.length + 1,
    }),
    omitNetwork: unexpectedOmission,
    omitEvent: unexpectedOmission,
  });
  const failed = requestFor("/extra.js");
  const failedResponse = responseFor(
    failed,
    404,
    "not read",
    fault === "headers" ? fault : undefined,
  );
  const successful = requestFor("/api/data");
  const successfulResponse = responseFor(
    successful,
    200,
    JSON.stringify({ value }),
    fault === "body" ? fault : undefined,
  );
  const close = async () => {
    await network.finish();
    return "terminated-owned-process" as const;
  };
  const session: BrowserScenarioSessionPort = {
    mode: "launch",
    processOwnership: "provider-owned",
    product: "Injected fixture browser",
    version: "fixture",
    initialUrl: origin,
    currentUrl: () => origin,
    sanitizeUrl: sanitizeBrowserUrl,
    setStep: (index) => {
      step = index;
    },
    nextEventSequence: () => events.length + 1,
    lastEventSequence: () => events.length,
    events: () => ({
      retained: events.length,
      dropped: 0,
      items: events,
      omissions: {
        by_kind: [],
        network_transactions: [],
        network_transaction_range: null,
      },
    }),
    eventLimitations: () => network.limitations(),
    perform: async () => {
      network.request(failed);
      network.response(failedResponse.source);
      network.failed(failed);
      network.request(successful);
      network.response(successfulResponse.source);
      network.finished(successful);
      await network.finish();
    },
    capture: async () =>
      browserStepArtifactsSchema.parse({
        screenshot: { state: "not_requested" },
        dom: { state: "not_requested" },
        accessibility: { state: "not_requested" },
        url: { state: "not_requested" },
        history: { state: "not_requested" },
        storage: { state: "not_requested" },
      }),
    cleanupLease: new AnalysisCleanupLease(async () => {
      await close();
    }, ["fixture-session"]),
    close,
    redactError: (error) =>
      error instanceof Error ? error.message : "fixture failure",
  };
  const provider = new PlaywrightBrowserScenarioProvider(async () => session);
  const result = await provider.captureScenario(scenario);
  if (!result.ok) throw result.error;
  return {
    capture: result.value,
    failedBodyReads: failedResponse.bodyReads(),
    gaps: network.limitations(),
  };
};
