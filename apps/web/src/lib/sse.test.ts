import { describe, expect, it } from "vitest";
import { createSseParser } from "./sse";

function collect(chunks: string[]): string[] {
  const events: string[] = [];
  const parser = createSseParser((data) => events.push(data));
  for (const chunk of chunks) parser.push(chunk);
  parser.end();
  return events;
}

describe("createSseParser", () => {
  it("delivers one payload per blank-line terminated event", () => {
    expect(collect(['data: {"a":1}\n\ndata: {"b":2}\n\n'])).toEqual(['{"a":1}', '{"b":2}']);
  });

  it("reassembles events split across chunks", () => {
    expect(collect(['data: {"a"', ':1}\n', "\ndata: x", "\n\n"])).toEqual(['{"a":1}', "x"]);
  });

  it("ignores keepalive comments and unknown fields", () => {
    expect(collect([": keepalive\n\nevent: ping\nid: 3\n\ndata: ok\n\n"])).toEqual(["ok"]);
  });

  it("joins multi-line data and accepts CRLF line endings", () => {
    expect(collect(["data: first\r\ndata: second\r\n\r\n"])).toEqual(["first\nsecond"]);
  });

  it("flushes a trailing event when the stream ends without a blank line", () => {
    expect(collect(["data: last"])).toEqual(["last"]);
  });
});
