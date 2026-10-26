"""Compare the findings of two scans."""

from api.models.reports import AggregatedFinding


def compare_findings(
    base: list[AggregatedFinding], head: list[AggregatedFinding]
) -> tuple[list[AggregatedFinding], list[AggregatedFinding], list[AggregatedFinding]]:
    """Split findings into (new, fixed, unchanged) between a baseline and a later scan.

    Findings are matched by id; unchanged findings are taken from the later scan.
    """
    base_ids = {finding.id for finding in base}
    head_ids = {finding.id for finding in head}
    new = [finding for finding in head if finding.id not in base_ids]
    fixed = [finding for finding in base if finding.id not in head_ids]
    unchanged = [finding for finding in head if finding.id in base_ids]
    return new, fixed, unchanged
