from enum import StrEnum


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class RuleType(StrEnum):
    SIGMA = "sigma"
    SURICATA = "suricata"


class FeedRunStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
