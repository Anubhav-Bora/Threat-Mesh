from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

import networkx as nx
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import IOC, Campaign


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class ClusteringService:
    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], settings: Settings
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings

    async def rebuild(self) -> dict[str, int]:
        async with self.session_factory() as session:
            query = select(IOC).order_by(IOC.last_seen.desc()).limit(self.settings.cluster_max_iocs)
            indicators = list((await session.scalars(query)).all())
            graph = self.build_graph(indicators)
            by_id = {ioc.id: ioc for ioc in indicators}
            communities = [
                members
                for members in self.detect_communities(graph)
                if len({by_id[node_id].is_demo for node_id in members}) == 1
                and len({self._semantic_identity(by_id[node_id]) for node_id in members}) >= 2
            ]

            await session.execute(update(IOC).values(cluster_id=None))
            await session.flush()
            await session.execute(delete(Campaign))
            await session.flush()

            clustered_iocs = 0
            for members in communities:
                community_iocs = [by_id[node_id] for node_id in members]
                campaign = self.make_campaign(community_iocs)
                session.add(campaign)
                await session.flush()
                for ioc in community_iocs:
                    ioc.cluster_id = campaign.id
                    clustered_iocs += 1
            await session.commit()
        return {
            "iocs_considered": len(indicators),
            "campaigns_created": len(communities),
            "iocs_clustered": clustered_iocs,
        }

    def build_graph(self, indicators: list[IOC]) -> nx.Graph:
        graph = nx.Graph()
        for ioc in indicators:
            graph.add_node(ioc.id)

        by_indicator: dict[tuple[bool, object, str], list[IOC]] = defaultdict(list)
        by_family: dict[tuple[bool, str], list[IOC]] = defaultdict(list)
        by_asn: dict[tuple[bool, str], list[IOC]] = defaultdict(list)
        for ioc in indicators:
            by_indicator[(ioc.is_demo, ioc.ioc_type, ioc.indicator_key)].append(ioc)
            if ioc.malware_family:
                by_family[(ioc.is_demo, ioc.malware_family.lower())].append(ioc)
            if ioc.asn:
                by_asn[(ioc.is_demo, ioc.asn.upper())].append(ioc)

        for bucket in by_indicator.values():
            self._connect_bucket(graph, bucket, weight=3.0, require_time_overlap=False)
        for bucket in by_family.values():
            self._connect_bucket(graph, bucket, weight=1.5, require_time_overlap=True)
        for bucket in by_asn.values():
            self._connect_bucket(graph, bucket, weight=1.0, require_time_overlap=True)

        # Time can strengthen an existing semantic relationship, but never creates
        # an edge by itself. This prevents continuous feeds from becoming campaigns.
        window = timedelta(hours=self.settings.cluster_window_hours)
        by_id = {ioc.id: ioc for ioc in indicators}
        for left_id, right_id in list(graph.edges):
            left = by_id[left_id]
            right = by_id[right_id]
            if abs(_utc(right.first_seen) - _utc(left.first_seen)) <= window:
                self._add_weight(graph, left.id, right.id, 0.2)
        return graph

    def _connect_bucket(
        self,
        graph: nx.Graph,
        bucket: list[IOC],
        *,
        weight: float,
        require_time_overlap: bool,
    ) -> None:
        ordered = sorted(bucket, key=lambda item: _utc(item.first_seen))
        window = timedelta(hours=self.settings.cluster_window_hours)
        for index, left in enumerate(ordered):
            # Bound fan-out so popular malware families cannot create a quadratic graph.
            for right in ordered[index + 1 : index + 31]:
                if require_time_overlap and _utc(right.first_seen) - _utc(left.first_seen) > window:
                    break
                self._add_weight(graph, left.id, right.id, weight)

    @staticmethod
    def _add_weight(graph: nx.Graph, left: int, right: int, weight: float) -> None:
        if left == right:
            return
        previous = graph.get_edge_data(left, right, {}).get("weight", 0.0)
        graph.add_edge(left, right, weight=previous + weight)

    @staticmethod
    def detect_communities(graph: nx.Graph) -> list[set[int]]:
        if graph.number_of_edges() == 0:
            return []
        communities = nx.community.louvain_communities(graph, weight="weight", seed=42)
        return [set(community) for community in communities if len(community) >= 2]

    @staticmethod
    def _semantic_identity(ioc: IOC) -> tuple[str, str]:
        return ioc.ioc_type.value, ioc.indicator_key

    @staticmethod
    def make_campaign(indicators: list[IOC]) -> Campaign:
        provenances = {ioc.is_demo for ioc in indicators}
        if len(provenances) != 1:
            raise ValueError("campaign members must share one demo/live provenance")
        families = Counter(
            ioc.malware_family for ioc in indicators if ioc.malware_family is not None
        )
        asns = Counter(ioc.asn for ioc in indicators if ioc.asn is not None)
        countries = Counter(ioc.country for ioc in indicators if ioc.country is not None)
        technique_ids = sorted(
            {technique for ioc in indicators for technique in (ioc.attack_technique_ids or [])}
        )
        average_confidence = round(
            sum(ioc.confidence_score or 0.0 for ioc in indicators) / len(indicators), 1
        )
        indicator_counts = Counter((ioc.ioc_type.value, ioc.indicator_key) for ioc in indicators)
        family_indicators: dict[str, set[tuple[str, str]]] = defaultdict(set)
        asn_indicators: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for ioc in indicators:
            identity = (ioc.ioc_type.value, ioc.indicator_key)
            if ioc.malware_family:
                family_indicators[ioc.malware_family].add(identity)
            if ioc.asn:
                asn_indicators[ioc.asn.upper()].add(identity)
        unique_indicator_count = len(indicator_counts)
        observation_count = len(indicators)
        top_family = families.most_common(1)[0][0] if families else "Unattributed"
        top_asn = asns.most_common(1)[0][0] if asns else None
        label = f"{top_family} infrastructure"
        if top_asn:
            label += f" on {top_asn}"
        return Campaign(
            label=label[:180],
            first_seen=min(_utc(ioc.first_seen) for ioc in indicators),
            last_seen=max(_utc(ioc.last_seen) for ioc in indicators),
            ioc_count=unique_indicator_count,
            is_demo=provenances.pop(),
            shared_attributes={
                "relationship_evidence": {
                    "repeated_indicators": [
                        {
                            "ioc_type": ioc_type,
                            "indicator_key": indicator_key,
                            "observation_count": count,
                        }
                        for (ioc_type, indicator_key), count in sorted(
                            indicator_counts.items(), key=lambda item: (-item[1], item[0])
                        )
                        if count >= 2
                    ],
                    "malware_families": [
                        {"value": value, "unique_indicator_count": len(identities)}
                        for value, identities in sorted(
                            family_indicators.items(),
                            key=lambda item: (-len(item[1]), item[0].lower()),
                        )
                        if len(identities) >= 2
                    ],
                    "asns": [
                        {"value": value, "unique_indicator_count": len(identities)}
                        for value, identities in sorted(
                            asn_indicators.items(), key=lambda item: (-len(item[1]), item[0])
                        )
                        if len(identities) >= 2
                    ],
                },
                "observed_context": {
                    "malware_families": [key for key, _ in families.most_common(5)],
                    "asns": [key for key, _ in asns.most_common(5)],
                    "countries": [key for key, _ in countries.most_common(5)],
                    "sources": sorted({ioc.source_feed for ioc in indicators}),
                    "technique_ids": technique_ids,
                    "average_ioc_confidence": average_confidence,
                    "unique_indicator_count": unique_indicator_count,
                    "observation_count": observation_count,
                },
            },
        )
