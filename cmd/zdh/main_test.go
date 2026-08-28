package main

import (
	"strings"
	"testing"
)

func TestBuildReportZeroDependencies(t *testing.T) {
	got := buildReport()

	for _, want := range []string{
		"zdh " + version,
		"go:        go1.",
		"platform:  ",
		"module:    zerodeps/zdh",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("build report is missing %q:\n%s", want, got)
		}
	}

	// The claim the whole entry rests on, asserted against the binary's own
	// embedded module records. If a dependency ever creeps in, this fails
	// before the gate's dependency-graph check even runs.
	if !strings.Contains(got, "dependencies: 0\n") {
		t.Errorf("build report does not report zero dependencies:\n%s", got)
	}
	if strings.Contains(got, "  dep ") {
		t.Errorf("build report lists a dependency:\n%s", got)
	}
}

// A report that ends without a newline runs into the next line of a judge's
// terminal, and every line must be printable — this is the first output anyone
// sees from the binary.
func TestBuildReportShape(t *testing.T) {
	got := buildReport()
	if !strings.HasSuffix(got, "\n") {
		t.Error("build report does not end with a newline")
	}
	for i, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			t.Errorf("line %d is blank", i+1)
		}
		if strings.ContainsAny(line, "\r\t") {
			t.Errorf("line %d contains a carriage return or tab: %q", i+1, line)
		}
	}
}
