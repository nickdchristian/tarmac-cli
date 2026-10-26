"""The example GitHub Actions workflow works once copied, with nothing in it to edit but the Region."""

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / "examples" / "github" / "tarmac.yml"


def _steps(job: str) -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"][job]["steps"]


def test_the_role_comes_from_a_repository_variable_not_a_placeholder_account():
    # A placeholder account fails with a misleading OIDC error, after minutes of retries.
    text = WORKFLOW.read_text()
    assert "111111111111" not in text
    for job in ("deploy", "drift"):
        (creds,) = [s for s in _steps(job) if "configure-aws-credentials" in s.get("uses", "")]
        assert creds["with"]["role-to-assume"] == "${{ vars.TARMAC_ROLE_ARN }}"


def test_the_uv_cache_follows_the_tarmac_pin():
    # A config repository has no lockfile, so setup-uv's default glob matches nothing and warns on every run.
    for job in ("validate", "deploy", "drift"):
        (uv,) = [s for s in _steps(job) if "setup-uv" in s.get("uses", "")]
        assert uv["with"]["cache-dependency-glob"] == ".github/workflows/tarmac.yml"
