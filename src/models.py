from pydantic import BaseModel


class FindingOut(BaseModel):
    finding_id: str
    klass: str
    title: str
    severity: str
    function_id: str
    reachable: bool
    path: list[str]
    sink: str = ''
    evidence_cypher: str = ''
    explanation: str
    recommended_fix: str


class Report(BaseModel):
    project: str
    attack_surface: int
    findings: list[FindingOut]
    rejected: list[dict] = []
    mode: str = 'agent'
