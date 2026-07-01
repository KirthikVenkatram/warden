package appsec.gate_test

import data.appsec.gate

base_finding := {
	"cve": "CVE-2024-0001",
	"package": "example-pkg",
	"installed_version": "1.0.0",
	"fixed_version": "1.0.1",
	"severity": "low",
	"cvss": 3.1,
	"epss": 0.01,
	"kev": false,
	"scanner": "trivy",
	"repo": "org/repo",
}

decisions_for(finding, tests_green) := ds if {
	ds := gate.decisions with input as {
		"findings": [finding],
		"tests_green": tests_green,
	}
}

decision_for(finding, tests_green) := d if {
	ds := decisions_for(finding, tests_green)
	d := ds[0]
}

test_kev_blocks_even_at_low_cvss if {
	finding := object.union(base_finding, {"kev": true, "severity": "low", "cvss": 2.0, "epss": 0.01})
	d := decision_for(finding, true)
	d.action == "block"
	some r in d.reasons
	contains(r, "KEV")
}

test_quiet_high_severity_not_blocked if {
	finding := object.union(base_finding, {"kev": false, "severity": "high", "cvss": 7.5, "epss": 0.02})
	d := decision_for(finding, true)
	d.action != "block"
	d.action == "ask"
}

test_low_risk_with_fix_and_tests_green_is_auto if {
	finding := object.union(base_finding, {"kev": false, "severity": "low", "epss": 0.01})
	d := decision_for(finding, true)
	d.action == "auto"
	d.auto_fixable == true
}

test_low_risk_with_fix_and_tests_not_green_is_ask if {
	finding := object.union(base_finding, {"kev": false, "severity": "medium", "epss": 0.01})
	d := decision_for(finding, false)
	d.action == "ask"
	d.auto_fixable == true
}

test_no_fix_is_ignore if {
	finding := object.union(base_finding, {"kev": false, "severity": "low", "epss": 0.01, "fixed_version": null})
	d := decision_for(finding, true)
	d.action == "ignore"
	d.auto_fixable == false
}

test_critical_severity_blocks_even_without_kev if {
	finding := object.union(base_finding, {"kev": false, "severity": "critical", "epss": 0.01})
	d := decision_for(finding, true)
	d.action == "block"
}

test_high_severity_high_epss_blocks if {
	finding := object.union(base_finding, {"kev": false, "severity": "high", "epss": 0.9})
	d := decision_for(finding, true)
	d.action == "block"
}

test_custom_epss_threshold_from_input_policy if {
	finding := object.union(base_finding, {"kev": false, "severity": "high", "epss": 0.2})
	ds := gate.decisions with input as {
		"findings": [finding],
		"tests_green": true,
		"policy": {"epss_block_threshold": 0.1},
	}
	d := ds[0]
	d.action == "block"
}
