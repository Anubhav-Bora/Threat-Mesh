export const THREAT_FAMILY_COLORS = [
  "#22d3ee",
  "#8b5cf6",
  "#f43f5e",
  "#f59e0b",
  "#10b981",
  "#3b82f6",
  "#ec4899",
  "#f97316",
] as const;

export const threatFamilyColorIndex = (family: string) => {
  let hash = 2_166_136_261;
  for (let index = 0; index < family.length; index += 1)
    hash = Math.imul(hash ^ family.charCodeAt(index), 16_777_619);
  return (hash >>> 0) % THREAT_FAMILY_COLORS.length;
};

export const threatFamilyColor = (family: string) =>
  THREAT_FAMILY_COLORS[threatFamilyColorIndex(family)];
