"""Guards for CI/release workflow wiring that is otherwise only exercised on a real release."""

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _steps(name: str) -> list[dict]:
    wf = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    return [step for job in wf["jobs"].values() for step in job.get("steps", [])]


def test_release_please_dispatches_publish_at_the_release_tag_not_main():
    step = next(s for s in _steps("release-please.yml") if "gh workflow run publish.yml" in s.get("run", ""))

    assert step["env"]["RELEASE_TAG"] == "${{ steps.release.outputs.tag_name }}"
    assert '--ref "$RELEASE_TAG"' in step["run"]
    assert "--ref main" not in step["run"]


def test_ci_enforces_a_coverage_floor():
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")

    assert "--cov=tarmac" in ci
    assert "fail_under" in pyproject
