export type ArtifactFormat = "markdown" | "sigma" | "suricata";

export function markSyntheticArtifact(
  content: string,
  format: ArtifactFormat,
  isDemo: boolean,
) {
  if (!isDemo) return content;
  const notice = "SYNTHETIC DEMO — NOT LIVE THREAT INTELLIGENCE";
  const banner =
    format === "markdown"
      ? `> **${notice}**\n> Documentation-only identifiers; do not deploy to security controls.`
      : format === "sigma"
        ? `# ${notice}`
        : `/* ${notice} */`;
  return `${banner}\n\n${content}`;
}
