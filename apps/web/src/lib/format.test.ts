import { describe, expect, it } from "vitest";
import { formatDuration, formatRelative, hostnameOf, plural } from "./format";

describe("formatDuration", () => {
  it.each([
    [950, "950 ms"],
    [18_000, "18 s"],
    [64_000, "1 min 04"],
    [3_720_000, "1 h 02"],
  ])("formats %d ms as %s", (ms, expected) => {
    expect(formatDuration(ms)).toBe(expected);
  });
});

describe("formatRelative", () => {
  const now = new Date("2026-10-26T12:00:00Z");

  it("uses minutes under an hour", () => {
    expect(formatRelative("2026-10-26T11:48:00Z", now)).toBe("il y a 12 minutes");
  });

  it("uses days beyond a day", () => {
    expect(formatRelative("2026-10-23T12:00:00Z", now)).toBe("il y a 3 jours");
  });
});

describe("hostnameOf", () => {
  it("keeps the port", () => {
    expect(hostnameOf("http://localhost:3000/app")).toBe("localhost:3000");
  });

  it("returns the input when it is not a URL", () => {
    expect(hostnameOf("example.com")).toBe("example.com");
  });
});

describe("plural", () => {
  it("adds an s above one", () => {
    expect(plural(1, "scan")).toBe("1 scan");
    expect(plural(3, "scan")).toBe("3 scans");
  });
});
