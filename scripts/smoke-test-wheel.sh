#!/usr/bin/env bash
# Install the built wheel into a clean virtualenv and exercise what only a packaged install can break:
# entry point, bundled CloudFormation templates, bundled SCP policies, and config validation.
set -euo pipefail

wheel="${1:?usage: smoke-test-wheel.sh path/to/tarmac_cli-*.whl}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

required=(
  "tarmac/templates/policies/iam/tarmac-deployment.json"
  "tarmac/templates/cloudformation/organization-cloudtrail.yaml"
  "tarmac/templates/policies/scp/foundational-guardrails.json"
  "tarmac/py.typed"
)
listing="$(python3 -m zipfile -l "$wheel")"
for path in "${required[@]}"; do
  grep -q "$path" <<<"$listing" || { echo "wheel is missing $path" >&2; exit 1; }
done

if [[ -z "${TARMAC_BIN:-}" ]]; then
  uv venv --quiet "$work/venv"
  uv pip install --quiet --python "$work/venv/bin/python" "$wheel"
  TARMAC_BIN="$work/venv/bin/tarmac"
fi

cd "$work"
"$TARMAC_BIN" --version
"$TARMAC_BIN" bootstrap --help >/dev/null
"$TARMAC_BIN" init project/config --with-templates >/dev/null
test -f project/cloudformation/organization-cloudtrail.yaml
test -f project/policies/scp/foundational-guardrails.json
"$TARMAC_BIN" validate --config-dir project/config >/dev/null
echo "wheel smoke test passed"
