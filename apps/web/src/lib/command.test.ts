import { describe, expect, it } from "vitest";
import { buildCurlCommand } from "./command";

describe("buildCurlCommand", () => {
  it("posts the request body to the API", () => {
    const command = buildCurlCommand(
      { target: "https://example.com", profile: "quick", timeout: 300 },
      "http://localhost:8001",
    );
    expect(command).toBe(
      [
        "curl -X POST http://localhost:8001/api/scans/start \\",
        "  -H 'Content-Type: application/json' \\",
        `  -d '{"target":"https://example.com","profile":"quick","timeout":300}'`,
      ].join("\n"),
    );
  });

  it("escapes single quotes", () => {
    const command = buildCurlCommand(
      { target: "https://example.com/?q='x'", timeout: 300 },
      "http://localhost:8001",
    );
    expect(command).toContain(`q='\\''x'\\''`);
  });
});
