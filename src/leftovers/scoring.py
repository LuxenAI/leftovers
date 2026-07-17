from __future__ import annotations

import math
import re
from datetime import datetime

from .config import RepositoryConfig, ScoringConfig
from .models import IssueCandidate, ScoreBreakdown, utc_now

_URGENT = {"priority: high", "high priority", "regression", "critical", "p1", "p2"}
_MAINTAINER = {"help wanted", "good first issue", "accepting prs", "community"}
_RISK = {
    "security",
    "vulnerability",
    "authentication",
    "authorization",
    "cryptography",
    "release",
    "infrastructure",
    "breaking-change",
    "migration",
}
_CLARITY = re.compile(
    r"\b(expected|actual|reproduc|steps|acceptance|test|version|traceback|error)\b", re.I
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _labels(issue: IssueCandidate) -> set[str]:
    return {label.casefold().strip() for label in issue.labels}


def score_issue(
    issue: IssueCandidate,
    repository: RepositoryConfig,
    config: ScoringConfig,
    now: datetime | None = None,
) -> ScoreBreakdown:
    now = now or utc_now()
    labels = _labels(issue)
    age_days = max(0.0, (now - issue.created_at).total_seconds() / 86_400)
    updated_days = max(0.0, (now - issue.updated_at).total_seconds() / 86_400)
    body = issue.body or ""
    text = f"{issue.title}\n{body}"

    stars_signal = _clamp(math.log10(max(issue.repo.stars, 1)) / 5)
    repository_impact = _clamp(0.7 * repository.importance + 0.3 * stars_signal)
    urgency = 0.2
    if labels.intersection({"bug", "type: bug"}):
        urgency = 0.5
    if labels.intersection(_URGENT):
        urgency = 0.9
    user_demand = _clamp(math.log1p(issue.reactions + issue.comments) / math.log(25))
    maintainer_signal = 0.15
    if "help wanted" in labels:
        maintainer_signal = 0.85
    if "good first issue" in labels:
        maintainer_signal = max(maintainer_signal, 0.7)
    if issue.author_association in {"MEMBER", "OWNER", "COLLABORATOR"}:
        maintainer_signal = _clamp(maintainer_signal + 0.15)

    clarity_hits = len(set(match.casefold() for match in _CLARITY.findall(text)))
    clarity = _clamp(0.25 + min(len(text), 2_000) / 4_000 + clarity_hits * 0.08)
    tractability = clarity
    if "good first issue" in labels:
        tractability = max(tractability, 0.8)
    if len(body) > 8_000:
        tractability *= 0.75

    neglect = _clamp(math.log1p(age_days) / math.log(730))
    if updated_days > 365:
        neglect *= 0.6

    risk_hits = labels.intersection(_RISK)
    technical_risk = _clamp(0.15 + 0.3 * len(risk_hits))
    collision_risk = 1.0 if issue.assignees or issue.has_open_linked_pr else 0.0
    if issue.comments >= 20:
        collision_risk = max(collision_risk, 0.35)
    scope_uncertainty = 1.0 - clarity

    base = (
        config.repository_impact_weight * repository_impact
        + config.urgency_weight * urgency
        + config.user_demand_weight * user_demand
        + config.maintainer_signal_weight * maintainer_signal
        + config.tractability_weight * tractability
        + config.neglect_weight * neglect
    )
    penalty = (
        config.technical_risk_penalty * technical_risk
        + config.collision_risk_penalty * collision_risk
        + config.scope_uncertainty_penalty * scope_uncertainty
    )
    total = round(100 * _clamp(base - penalty))
    reasons = (
        f"curated impact={repository.importance:.2f}, stars={issue.repo.stars}",
        f"maintainer signal={maintainer_signal:.2f} from labels/author association",
        f"clarity={clarity:.2f}, age={age_days:.0f}d, last update={updated_days:.0f}d",
        f"risk={technical_risk:.2f}, collision={collision_risk:.2f}",
    )
    return ScoreBreakdown(
        repository_impact=round(repository_impact, 4),
        urgency=round(urgency, 4),
        user_demand=round(user_demand, 4),
        maintainer_signal=round(maintainer_signal, 4),
        tractability=round(tractability, 4),
        neglect=round(neglect, 4),
        technical_risk=round(technical_risk, 4),
        collision_risk=round(collision_risk, 4),
        scope_uncertainty=round(scope_uncertainty, 4),
        total=total,
        reasons=reasons,
    )
