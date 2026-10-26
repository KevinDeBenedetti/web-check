import { describe, expect, it } from "vitest";
import { groupScansBySite, recurringFindings, scanProgress } from "./sites";
import { makeFinding, makeResult, makeScan } from "./testing";

describe("groupScansBySite", () => {
  const scans = [
    makeScan({ scan_id: "4", target: "https://a.example.com", status: "running", score: 100, started_at: "2026-10-26T12:00:00Z" }),
    makeScan({ scan_id: "3", target: "https://b.example.com/", score: 70, started_at: "2026-10-26T11:00:00Z" }),
    makeScan({ scan_id: "2", target: "https://a.example.com", score: 80, started_at: "2026-10-25T10:00:00Z" }),
    makeScan({ scan_id: "1", target: "https://a.example.com", score: 60, started_at: "2026-10-24T10:00:00Z" }),
  ];

  it("groups by host, newest activity first", () => {
    expect(groupScansBySite(scans).map((site) => site.host)).toEqual([
      "a.example.com",
      "b.example.com",
    ]);
  });

  it("keeps the latest finished scan, the running one and the score history", () => {
    const [site] = groupScansBySite(scans);
    expect(site?.latest?.scan_id).toBe("2");
    expect(site?.running?.scan_id).toBe("4");
    expect(site?.scores).toEqual([60, 80]);
    expect(site?.scanCount).toBe(3);
  });
});

describe("recurringFindings", () => {
  it("only keeps findings shared by at least two sites", () => {
    const sites = groupScansBySite([
      makeScan({
        target: "https://a.test",
        results: [makeResult("headers", [makeFinding("HSTS", "medium"), makeFinding("only a")])],
      }),
      makeScan({
        target: "https://b.test",
        results: [makeResult("nikto", [makeFinding("hsts", "high")])],
      }),
    ]);
    expect(recurringFindings(sites)).toEqual([
      { key: "hsts", title: "HSTS", severity: "high", hosts: ["a.test", "b.test"] },
    ]);
  });
});

describe("scanProgress", () => {
  it("is the share of modules with a result while running", () => {
    const scan = makeScan({
      status: "running",
      modules: ["headers", "dns", "nuclei", "nikto"],
      results: [makeResult("headers", [])],
    });
    expect(scanProgress(scan)).toBe(0.25);
  });

  it("is complete once the scan has finished", () => {
    expect(scanProgress(makeScan({ modules: ["headers", "dns"] }))).toBe(1);
  });
});
