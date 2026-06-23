package main

import (
	"sort"
)

// Status is the outcome of a single check.
type Status int

const (
	StatusOK Status = iota
	StatusInfo
	StatusWarn
	StatusFail
)

func (s Status) Label() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusInfo:
		return "INFO"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	}
	return "?"
}

// weight is used to sort findings so the most serious surface first.
func (s Status) weight() int {
	switch s {
	case StatusFail:
		return 0
	case StatusWarn:
		return 1
	case StatusInfo:
		return 2
	case StatusOK:
		return 3
	}
	return 4
}

// Finding is a single posture observation, written in plain language.
type Finding struct {
	Category string // grouping, e.g. "System", "Data & Recovery"
	Title    string // short name of what was checked
	Status   Status
	Detail   string // what we actually observed
	Why      string // why it matters (only for Warn/Fail)
	Fix      string // concrete next step (only for Warn/Fail)
}

// Report is the full result of a host scan.
type Report struct {
	Tool     string
	Version  string
	When     string
	Host     HostInfo
	Findings []Finding
}

// HostInfo is basic identity collected up front.
type HostInfo struct {
	Hostname string
	OS       string // "windows" / "linux"
	OSName   string // friendly, e.g. "Ubuntu 24.04 LTS" or "Windows 11 Pro"
	Arch     string
	Kernel   string
	User     string
}

// add appends a finding.
func (r *Report) add(f Finding) { r.Findings = append(r.Findings, f) }

// sortFindings orders by severity (Fail first) then category.
func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Status.weight() != b.Status.weight() {
			return a.Status.weight() < b.Status.weight()
		}
		return a.Category < b.Category
	})
}

// counts returns how many findings fall into each status.
func (r *Report) counts() (fail, warn, ok, info int) {
	for _, f := range r.Findings {
		switch f.Status {
		case StatusFail:
			fail++
		case StatusWarn:
			warn++
		case StatusOK:
			ok++
		case StatusInfo:
			info++
		}
	}
	return
}

// score is a simple 0-100 posture score: full credit for OK, none for Fail,
// half for Warn; Info is ignored. It is a rough indicator, not a guarantee.
func (r *Report) score() int {
	var got, max float64
	for _, f := range r.Findings {
		switch f.Status {
		case StatusOK:
			got += 1
			max += 1
		case StatusWarn:
			got += 0.5
			max += 1
		case StatusFail:
			max += 1
		}
	}
	if max == 0 {
		return 100
	}
	return int((got / max) * 100)
}
