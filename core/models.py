from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Action(str, Enum):
    AUTO = "auto"
    ASK = "ask"
    BLOCK = "block"
    IGNORE = "ignore"


class Finding(BaseModel):
    cve: str
    package: str
    installed_version: str
    fixed_version: str | None = None
    severity: Severity
    cvss: float
    epss: float = 0.0
    kev: bool = False
    scanner: str
    repo: str


class Decision(BaseModel):
    cve: str
    package: str
    action: Action
    reasons: list[str]
    auto_fixable: bool


class ScanSummary(BaseModel):
    repo: str
    scanner: str
    total: int
    auto: int
    ask: int
    block: int
    ignore: int


class PRResult(BaseModel):
    cve: str
    package: str
    repo: str
    branch: str
    fixed_version: str
    url: str
    number: int
    merged: bool = False
