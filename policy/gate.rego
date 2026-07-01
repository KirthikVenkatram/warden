package appsec.gate

# input shape:
# {
#   "findings": [Finding, ...],
#   "tests_green": bool,
#   "policy": {"epss_block_threshold": 0.5}   # optional
# }

default epss_block_threshold := 0.5

epss_block_threshold := t if {
	t := input.policy.epss_block_threshold
}

decisions := [decide(f) | some f in input.findings]

# block: any block-reason applies, regardless of fix availability.
decide(finding) := result if {
	reasons := block_reasons(finding)
	count(reasons) > 0
	result := {
		"cve": finding.cve,
		"package": finding.package,
		"action": "block",
		"reasons": reasons,
		"auto_fixable": has_fix(finding),
	}
}

# auto: no block-reason, a fix exists, low-risk, and tests are green.
decide(finding) := result if {
	count(block_reasons(finding)) == 0
	has_fix(finding)
	low_risk(finding)
	input.tests_green == true
	result := {
		"cve": finding.cve,
		"package": finding.package,
		"action": "auto",
		"reasons": ["low risk (severity and EPSS below threshold) and tests are green"],
		"auto_fixable": true,
	}
}

# ask: no block-reason, a fix exists, but not eligible for auto.
decide(finding) := result if {
	count(block_reasons(finding)) == 0
	has_fix(finding)
	not auto_eligible(finding)
	result := {
		"cve": finding.cve,
		"package": finding.package,
		"action": "ask",
		"reasons": ask_reasons(finding),
		"auto_fixable": true,
	}
}

# ignore: no block-reason and no fix available.
decide(finding) := result if {
	count(block_reasons(finding)) == 0
	not has_fix(finding)
	result := {
		"cve": finding.cve,
		"package": finding.package,
		"action": "ignore",
		"reasons": ["no fixed version available"],
		"auto_fixable": false,
	}
}

auto_eligible(finding) if {
	low_risk(finding)
	input.tests_green == true
}

low_risk(finding) if {
	finding.severity in {"low", "medium"}
	finding.epss < epss_block_threshold
}

# has_fix is total: always true or false, never undefined, so it can be
# embedded directly as a Decision field.
has_fix(finding) := true if object.get(finding, "fixed_version", null) != null

has_fix(finding) := false if object.get(finding, "fixed_version", null) == null

block_reasons(finding) := reasons if {
	kev_reasons := [r |
		finding.kev == true
		r := "on CISA KEV — known exploited in the wild"
	]
	critical_reasons := [r |
		finding.severity == "critical"
		r := "severity is critical"
	]
	epss_reasons := [r |
		finding.severity in {"high", "critical"}
		finding.epss >= epss_block_threshold
		r := sprintf("EPSS %.2f meets or exceeds the block threshold %.2f at %s severity", [finding.epss, epss_block_threshold, finding.severity])
	]
	reasons := array.concat(array.concat(kev_reasons, critical_reasons), epss_reasons)
}

ask_reasons(finding) := reasons if {
	extra := array.concat(
		[r |
			not low_risk(finding)
			r := sprintf("severity %s / EPSS %.2f is above the low-risk threshold", [finding.severity, finding.epss])
		],
		[r |
			input.tests_green != true
			r := "automated tests are not green"
		],
	)
	reasons := array.concat(["fix available; requires human approval"], extra)
}
