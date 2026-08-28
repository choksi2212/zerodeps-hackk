package frame

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// matrixRows is the number of rows in the frame-layer validation matrix, which is
// the design document's enumeration of every framing rule in RFC 9113 §4 and §6
// that a conformance suite checks.
const matrixRows = 41

// matrixAnnotation matches a reference to one or more matrix rows in a comment:
// "matrix row 12", "Matrix rows 3 and 4", "matrix rows 17, 18 and 19".
var matrixAnnotation = regexp.MustCompile(`[Mm]atrix rows? (\d+(?:(?:,| and) ?\d+)*)`)

// matrixNumber pulls the individual row numbers out of such a list.
var matrixNumber = regexp.MustCompile(`\d+`)

// commentWrap matches the line break inside a multi-line comment.
//
// Comments here wrap at the same width as the code, so an annotation lands across
// two lines as often as not — "…is matrix\n// row 10." A checker that missed those
// would report gaps that are not there and, worse, would let a real gap hide
// behind a plausible-looking wrap. Joining the lines first is simpler than a
// pattern that tolerates them.
var commentWrap = regexp.MustCompile(`\n[ \t]*//[ \t]*`)

// spaceRun collapses the runs of blanks that unwrapping leaves behind — a comment
// broken across a blank "//" line unwraps to two spaces where the annotation has
// one.
var spaceRun = regexp.MustCompile(`[ \t]+`)

// TestValidationMatrixIsAnnotated checks that every row of the validation matrix
// is claimed by a comment somewhere in this package, by reading the package's own
// source.
//
// The matrix is the list of rules this layer exists to enforce, so a row nobody
// mentions is a rule nobody implemented — and the failure mode is silence: the
// code compiles, the other tests pass, and the gap only appears when a conformance
// suite finds it. Grepping for a row number should land on either the test that
// covers it or the comment explaining which later package owns it.
//
// A comment convention is normally not worth a test. This one is, because the
// matrix is what the design document offers as evidence of coverage, and evidence
// that nothing checks is an assertion.
func TestValidationMatrixIsAnnotated(t *testing.T) {
	claimed := map[int][]string{}
	for _, path := range packageSources(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, row := range claimedMatrixRows(string(src)) {
			claimed[row] = append(claimed[row], filepath.Base(path))
		}
	}

	var missing []string
	for row := 1; row <= matrixRows; row++ {
		if len(claimed[row]) == 0 {
			missing = append(missing, strconv.Itoa(row))
		}
	}
	if len(missing) != 0 {
		t.Errorf("validation matrix rows %s are not mentioned anywhere in the package; "+
			"each row needs either a test that covers it or a comment naming the package "+
			"that will", strings.Join(missing, ", "))
	}

	// A row number outside the matrix is a typo, and a typo here is worse than no
	// annotation: it makes a row look covered while the real one is missed.
	for row, files := range claimed {
		if row < 1 || row > matrixRows {
			t.Errorf("%s cites matrix row %d, but the matrix has rows 1 to %d",
				strings.Join(files, ", "), row, matrixRows)
		}
	}
}

// claimedMatrixRows returns every matrix row number cited in src, in no
// particular order and with duplicates.
func claimedMatrixRows(src string) []int {
	text := spaceRun.ReplaceAllString(commentWrap.ReplaceAllString(src, " "), " ")
	var rows []int
	for _, m := range matrixAnnotation.FindAllStringSubmatch(text, -1) {
		for _, digits := range matrixNumber.FindAllString(m[1], -1) {
			// The pattern only ever captures digit runs, so Atoi cannot fail on
			// anything it produces; a row number too large for an int would, and
			// that is a typo worth surfacing rather than silently dropping.
			n, err := strconv.Atoi(digits)
			if err != nil {
				rows = append(rows, matrixRows+1)
				continue
			}
			rows = append(rows, n)
		}
	}
	return rows
}

// TestMatrixAnnotationParsing exercises the extraction on the forms the package
// actually uses, including the two that a naive pattern gets wrong: a comment that
// wrapped mid-phrase, and a row number followed by punctuation.
//
// It is here because TestValidationMatrixIsAnnotated passing proves nothing on its
// own — a checker that found no annotations at all and a checker that found them
// all would both be silent about it. These cases are what say which one it is.
func TestMatrixAnnotationParsing(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []int
	}{
		{"one row", "// This is matrix row 12.", []int{12}},
		{"two rows", "// Matrix rows 3 and 4 seen through DATA.", []int{3, 4}},
		{"three rows", "// matrix rows 17, 18 and 19. Three identifiers.", []int{17, 18, 19}},
		{"possessive", "// Matrix row 26's boundary from the legal side.", []int{26}},
		{"at the end of a sentence", "// …and that is matrix row 37", []int{37}},
		{"wrapped after matrix", "// behaviour, and it is matrix\n// row 10. A receiver", []int{10}},
		{"wrapped before the list", "// enforced here. Matrix\n// rows 38 and 39 cover it", []int{38, 39}},
		{"wrapped inside the list", "// Matrix rows 30\n// and 31 are in internal/flow", []int{30, 31}},
		{"wrapped across a blank comment line", "// matrix\n//\n// row 24 is elsewhere", []int{24}},
		{"indented comment", "\t\t\t// Matrix row 40. Closing the\n\t\t\t// stream is later.", []int{40}},
		{"several in one file", "// matrix row 1\nfunc x() {}\n// matrix row 2", []int{1, 2}},
		{"no annotation", "// A comment about row 5 of something else.", nil},
		{"not a row at all", "// The matrix rows are listed in the design document.", nil},
		{"out of range", "// matrix row 99 does not exist.", []int{99}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := claimedMatrixRows(tc.src)
			if len(got) != len(tc.want) {
				t.Fatalf("claimedMatrixRows(%q) = %v, want %v", tc.src, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("claimedMatrixRows(%q) = %v, want %v", tc.src, got, tc.want)
				}
			}
		})
	}
}

// packageSources lists the .go files of this package. `go test` runs with the
// package directory as its working directory, which is what makes this possible
// without knowing where the repository is checked out.
//
// This file is excluded. It quotes annotations as test fixtures rather than
// claiming rows, so scanning it would have the checker read its own examples —
// including the deliberately out-of-range one — as coverage of the real matrix.
func packageSources(t *testing.T) []string {
	t.Helper()
	const fixtures = "matrix_test.go"

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing the package sources: %v", err)
	}
	var sources []string
	found := false
	for _, p := range paths {
		if filepath.Base(p) == fixtures {
			found = true
			continue
		}
		sources = append(sources, p)
	}
	if !found {
		t.Fatalf("%s is not in the package directory; if it was renamed, update the "+
			"exclusion here or its fixtures will be read as real annotations", fixtures)
	}
	if len(sources) == 0 {
		t.Fatal("found no .go files in the package directory")
	}
	return sources
}
