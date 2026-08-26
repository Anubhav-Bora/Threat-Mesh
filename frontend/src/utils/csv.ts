const hasFormulaPrefix = (text: string) => {
  let index = 0;
  while (index < text.length && text.charCodeAt(index) <= 0x20) index += 1;
  return "=+-@".includes(text[index] ?? "");
};

export function escapeCsvCell(value: unknown): string {
  const text = String(value ?? "");
  const neutralized = hasFormulaPrefix(text) ? `'${text}` : text;
  return `"${neutralized.replaceAll('"', '""')}"`;
}

export function rowsToCsv(rows: unknown[][]): string {
  return rows.map((row) => row.map(escapeCsvCell).join(",")).join("\r\n");
}
