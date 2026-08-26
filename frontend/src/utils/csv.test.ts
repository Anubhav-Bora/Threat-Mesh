import { describe, expect, it } from "vitest";
import { escapeCsvCell, rowsToCsv } from "./csv";

describe("CSV export hardening", () => {
  it.each([
    '=WEBSERVICE("bad")',
    "+cmd",
    "-2+3",
    "@SUM(A1:A2)",
    "  =1+1",
    '\n=HYPERLINK("bad")',
    "\u000b+cmd",
  ])("neutralizes spreadsheet formula input %s", (value) => {
    expect(escapeCsvCell(value)).toMatch(/^"'/);
  });

  it("retains RFC 4180 quoting after neutralization", () => {
    expect(rowsToCsv([["safe,value", '=HYPERLINK("x")']])).toBe(
      '"safe,value","\'=HYPERLINK(""x"")"',
    );
  });
});
