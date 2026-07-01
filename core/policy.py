import json
import os
import subprocess
from pathlib import Path

from core.models import Decision, Finding

_GATE_REGO = Path(__file__).resolve().parent.parent / "policy" / "gate.rego"


def evaluate(findings: list[Finding], tests_green: bool, threshold: float = 0.5) -> list[Decision]:
    """Evaluate findings against policy/gate.rego and return the autonomy decisions."""
    opa_binary = os.environ.get("OPA_BINARY", "opa")
    input_doc = {
        "findings": [f.model_dump(mode="json") for f in findings],
        "tests_green": tests_green,
        "policy": {"epss_block_threshold": threshold},
    }
    result = subprocess.run(
        [opa_binary, "eval", "-d", str(_GATE_REGO), "-I", "data.appsec.gate.decisions", "--format", "json"],
        input=json.dumps(input_doc),
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    decisions_raw = payload["result"][0]["expressions"][0]["value"]
    return [Decision.model_validate(d) for d in decisions_raw]
