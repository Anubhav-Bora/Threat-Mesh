import type { Campaign } from "../types";

const positions = [
  [260, 120],
  [112, 65],
  [420, 62],
  [86, 210],
  [426, 220],
  [208, 258],
  [330, 270],
  [176, 155],
  [355, 150],
];

export function CampaignGraph({ campaign }: { campaign: Campaign }) {
  const nodes = [
    { id: campaign.id, label: campaign.label, kind: "campaign", size: 32 },
    ...campaign.relationshipEvidence.repeatedIndicators.map((item, index) => ({
      id: `indicator-${index}`,
      label: `${item.iocType}: ${item.indicatorKey}`,
      kind: "indicator",
      size: 19,
    })),
    ...campaign.relationshipEvidence.malwareFamilies.map((item, index) => ({
      id: `malware-${index}`,
      label: item.value,
      kind: "malware",
      size: 22,
    })),
    ...campaign.relationshipEvidence.asns.map((item, index) => ({
      id: `asn-${index}`,
      label: item.value,
      kind: "infra",
      size: 18,
    })),
  ].slice(0, positions.length);
  return (
    <div className="campaign-graph">
      <svg
        viewBox="0 0 520 320"
        role="img"
        aria-label={`Relationship graph for ${campaign.label}`}
      >
        <defs>
          <radialGradient id="campaign-node">
            <stop offset="0" stopColor="#8b83ff" stopOpacity=".95" />
            <stop offset="1" stopColor="#655bd6" stopOpacity=".45" />
          </radialGradient>
        </defs>
        {nodes.slice(1).map((node, index) => {
          const [x = 0, y = 0] = positions[index + 1] ?? [];
          return (
            <line
              key={`edge-${node.id}`}
              x1="260"
              y1="120"
              x2={x}
              y2={y}
              className={`graph-edge graph-edge--${node.kind}`}
            />
          );
        })}
        {nodes.map((node, index) => {
          const [x = 0, y = 0] = positions[index] ?? [];
          return (
            <g key={node.id} className={`graph-node graph-node--${node.kind}`}>
              <circle
                cx={x}
                cy={y}
                r={node.size + 8}
                className="graph-node__halo"
              />
              <circle cx={x} cy={y} r={node.size} />
              <text x={x} y={y + node.size + 17} textAnchor="middle">
                {node.label.length > 20
                  ? `${node.label.slice(0, 18)}…`
                  : node.label}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="graph-key">
        <span>
          <i className="key-dot key-dot--campaign" />
          Campaign
        </span>
        <span>
          <i className="key-dot key-dot--indicator" />
          Repeated indicator
        </span>
        <span>
          <i className="key-dot key-dot--malware" />
          Repeated family
        </span>
        <span>
          <i className="key-dot key-dot--infra" />
          Repeated ASN
        </span>
      </div>
    </div>
  );
}
