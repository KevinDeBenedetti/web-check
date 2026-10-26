import { describe, expect, it } from "vitest";
import { canonicalModule, moduleEngine, moduleLabel, scoreBand } from "./labels";

describe("module labels", () => {
  it("uses the French copy for known modules", () => {
    expect(moduleLabel("testssl")).toBe("Chiffrement TLS");
    expect(moduleEngine("testssl")).toBe("SSLyze");
  });

  it("resolves names stored by older scans", () => {
    expect(canonicalModule("sslyze")).toBe("testssl");
    expect(canonicalModule("nuclei")).toBe("nuclei");
    expect(moduleLabel("sslyze")).toBe("Chiffrement TLS");
    expect(moduleLabel("dns_enum")).toBe("DNS et e-mail");
  });

  it("falls back to the API name, then the id", () => {
    expect(moduleLabel("ffuf", "Fuzzer")).toBe("Fuzzer");
    expect(moduleLabel("ffuf")).toBe("ffuf");
  });
});

describe("scoreBand", () => {
  it.each([
    [100, "good"],
    [80, "good"],
    [79, "fair"],
    [60, "fair"],
    [59, "poor"],
  ])("%d is %s", (score, band) => {
    expect(scoreBand(score)).toBe(band);
  });
});
