import { describe, expect, it } from "vitest";
import { countBySeverity, dedupeFindings, findingKey, findingToMarkdown } from "./findings";
import { makeFinding, makeResult } from "./testing";

describe("findingKey", () => {
  it("ignores case and repeated whitespace", () => {
    expect(findingKey("  Missing   HSTS ")).toBe(findingKey("missing hsts"));
  });
});

describe("dedupeFindings", () => {
  it("merges findings across modules and keeps the highest severity", () => {
    const findings = dedupeFindings([
      makeResult("headers", [makeFinding("Missing HSTS", "medium"), makeFinding("b", "low")]),
      makeResult("nikto", [makeFinding("missing hsts", "high")]),
    ]);
    expect(findings.map((f) => [f.title, f.severity, f.sources])).toEqual([
      ["Missing HSTS", "high", ["headers", "nikto"]],
      ["b", "low", ["headers"]],
    ]);
  });
});

describe("countBySeverity", () => {
  it("counts every severity", () => {
    expect(countBySeverity([makeFinding("a", "high"), makeFinding("b", "high")])).toEqual({
      critical: 0,
      high: 2,
      medium: 0,
      low: 0,
      info: 0,
    });
  });
});

describe("findingToMarkdown", () => {
  it("includes remediation and reference when present", () => {
    const markdown = findingToMarkdown(
      {
        ...makeFinding("Cookie without Secure", "high"),
        remediation: "Add Secure",
        reference: "https://example.org/doc",
        sources: ["headers"],
      },
      "https://example.com",
    );
    expect(markdown).toContain("### [HIGH] Cookie without Secure");
    expect(markdown).toContain("**Correction :** Add Secure");
    expect(markdown).toContain("Référence : https://example.org/doc");
  });
});
