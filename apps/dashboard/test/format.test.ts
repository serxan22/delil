import { describe, expect, it } from "vitest";
import { bytes, dateTime, num, relative, short } from "../src/lib/format";

describe("format", () => {
  it("formats numbers, sizes and hashes", () => {
    expect(num(18421)).toBe("18,421");
    expect(bytes(26289)).toBe("25.7 KB");
    expect(short("cba241859d367f2cbc7f", 8)).toBe("cba24185…");
  });
  it("formats times in UTC", () => {
    expect(dateTime("2026-10-02T10:10:35.840238Z")).toBe("2026-10-02 10:10:35 UTC");
    const now = Date.parse("2026-10-02T12:00:00Z");
    expect(relative("2026-10-02T11:59:30Z", now)).toBe("just now");
    expect(relative("2026-10-02T09:00:00Z", now)).toBe("3 hours ago");
    expect(relative(undefined, now)).toBe("never");
  });
});
