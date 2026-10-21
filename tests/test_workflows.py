"""Guards for CI/release workflow wiring that is otherwise only exercised on a real release."""

import re
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


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def test_fromjson_always_has_a_fallback_for_missing_outputs():
    """``fromJSON('')`` is a template error even inside a skipped step, which broke release-please on release-only runs."""
    for path in _workflow_files():
        for expr in re.findall(r"fromJSON\(([^)]*)\)", path.read_text(encoding="utf-8")):
            assert "||" in expr, f"{path.name}: fromJSON({expr}) has no fallback for an empty value"


def test_gh_steps_know_their_repository_without_a_checkout():
    """``gh`` infers the repository from a git checkout; without one it needs GH_REPO (this stranded v0.1.8)."""
    for path in _workflow_files():
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in wf["jobs"].items():
            checked_out = False
            for step in job.get("steps", []):
                if "actions/checkout" in step.get("uses", "") and "if" not in step:
                    checked_out = True
                uses_gh = re.search(r"(^|\s)gh\s", step.get("run", ""))
                env = {**wf.get("env", {}), **job.get("env", {}), **step.get("env", {})}
                if uses_gh and not checked_out:
                    assert "GH_REPO" in env, (
                        f"{path.name}:{job_name}: step '{step.get('name')}' runs gh without GH_REPO"
                    )
