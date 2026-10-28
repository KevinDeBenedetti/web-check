import { describe, expect, it } from "vitest";
import { filenameFromDisposition, isHttpUrl } from "./url";

describe("isHttpUrl", () => {
  it("accepts absolute http and https URLs", () => {
    expect(isHttpUrl("https://example.com/path?q=1")).toBe(true);
    expect(isHttpUrl("http://staging.example.com:8080")).toBe(true);
  });

  it("rejects anything a link must not execute or that has no host", () => {
    for (const value of ["javascript:alert(1)", "data:text/html,x", "ftp://example.com", "example.com", "", "https://"]) {
      expect(isHttpUrl(value), value).toBe(false);
    }
  });
});

describe("filenameFromDisposition", () => {
  it("reads a quoted file name", () => {
    expect(filenameFromDisposition('attachment; filename="web-check-20261026-1000-aaaa.sarif"')).toBe(
      "web-check-20261026-1000-aaaa.sarif",
    );
  });

  it("keeps a plain file name only", () => {
    expect(filenameFromDisposition('attachment; filename="../../x.md"')).toBe("....x.md");
    expect(filenameFromDisposition("inline")).toBeNull();
    expect(filenameFromDisposition(null)).toBeNull();
  });
});
