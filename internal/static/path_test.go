package static

import (
	"strings"
	"testing"
)

// resolve is the whole attack surface of this package, so this file is longer than the
// code it tests and is meant to be. Every case here is a request somebody has actually
// sent to somebody's server.

// TestResolveTargets is resolve's whole behaviour as a table: what a target resolves to,
// whether it asked for a directory, and whether it names anything at all.
func TestResolveTargets(t *testing.T) {
	for _, c := range []struct {
		why    string
		target string
		name   string
		slash  bool
		ok     bool
	}{
		// The ordinary cases, which are also the ones a break would break first.
		{"the root", "/", ".", true, true},
		{"a file", "/index.html", "index.html", false, true},
		{"a nested file", "/a/b/c.txt", "a/b/c.txt", false, true},
		{"a directory", "/assets/", "assets", true, true},
		{"a directory without its slash", "/assets", "assets", false, true},

		// Empty segments. Neither names anything, and collapsing them is what makes
		// "/a//b" and "/a/b" one resource rather than two with one cache entry each.
		{"a doubled root", "//", ".", true, true},
		{"a doubled separator", "/a//b", "a/b", false, true},
		{"three separators", "/a///b", "a/b", false, true},

		// §5.2.4's dot segments, which is the traversal every scanner tries first.
		{"a bare dot", "/.", ".", false, true},
		{"a bare double dot", "/..", ".", false, true},
		{"a dot in the middle", "/a/./b", "a/b", false, true},
		{"a pop", "/a/../b", "b", false, true},
		{"a pop past the root", "/../../etc/passwd", "etc/passwd", false, true},
		{"pops and dots together", "/a/./../../b", "b", false, true},
		{"a pop to the root", "/a/..", ".", false, true},
		{"a pop to the root with a slash", "/a/../", ".", true, true},
		{"more pops than segments", "/a/../../../..", ".", false, true},

		// The same traversal, encoded. This is the case that distinguishes a decode
		// before the split from a decode after it: "%2e%2e" is ".." and has to be
		// treated as one, where "%2f" is a separator and must not be.
		{"an encoded double dot", "/%2e%2e/%2e%2e/etc/passwd", "etc/passwd", false, true},
		{"an encoded dot", "/a/%2e/b", "a/b", false, true},
		{"a half-encoded double dot", "/a/.%2e/b", "b", false, true},
		{"an uppercase encoded double dot", "/%2E%2E/x", "x", false, true},
		{"an encoded separator", "/a%2fb", "", false, false},
		{"an encoded separator in a traversal", "/a%2f..%2fb", "", false, false},
		{"an uppercase encoded separator", "/a%2Fb", "", false, false},
		{"an encoded backslash", "/a%5cb", "", false, false},

		// A raw backslash, which internal/request lets through because §8.3.1 has
		// nothing against it and which is a separator on exactly one platform.
		{"a raw backslash", `/dir\..\..\secret`, "", false, false},
		{"a raw backslash alone", `/a\b`, "", false, false},

		// Percent-encoding that is not encoding anything.
		{"a bare percent", "/%", "", false, false},
		{"one hex digit", "/%2", "", false, false},
		{"no hex digits", "/%zz", "", false, false},
		{"one bad digit", "/%2z", "", false, false},

		// A bad *second* digit whose first digit alone would decode to something a name
		// may hold: "%4z" read as "%40" is "@". A decoder that checked only the first
		// digit would answer this one with a file name.
		{"a bad second digit", "/%4z", "", false, false},
		{"a percent at the end of a segment", "/a%/b", "", false, false},
		{"an encoded percent", "/a%25b", "a%b", false, true},

		// Decoded octets that no name may contain. Each of these is refused by the same
		// rule that refuses the raw octet, which is the point: internal/request has
		// already refused a raw NUL, and a decode is where one comes back.
		{"an encoded NUL", "/%00", "", false, false},
		{"an encoded newline", "/a%0ab", "", false, false},
		{"an encoded return", "/a%0db", "", false, false},
		{"an encoded space", "/a%20b", "", false, false},
		{"a trailing encoded space", "/index.html%20", "", false, false},
		{"an encoded DEL", "/a%7fb", "", false, false},
		{"an encoded question mark", "/a%3fb", "", false, false},
		{"an encoded asterisk", "/a%2ab", "", false, false},
		{"an encoded colon", "/a%3ab", "", false, false},
		{"an encoded pipe", "/a%7cb", "", false, false},
		{"an encoded angle bracket", "/a%3cb", "", false, false},
		{"an encoded quote", `/a%22b`, "", false, false},

		// Octets that survive, because a file name is octets and not ASCII. Both halves
		// of a UTF-8 sequence are above 0x7f and neither is a separator on any platform.
		{"an encoded letter", "/%41", "A", false, true},
		{"encoded UTF-8", "/caf%c3%a9.txt", "caf\u00e9.txt", false, true},
		{"raw UTF-8", "/caf\u00e9.txt", "caf\u00e9.txt", false, true},
		{"a tilde", "/a~b", "a~b", false, true},
		{"an encoded tilde", "/a%7eb", "a~b", false, true},

		// The alternate-data-stream names, which are a second name for one file and
		// a way past an extension check.
		{"a stream", "/file.txt:stream", "", false, false},
		{"the default stream", "/file.txt::$DATA", "", false, false},
		{"a drive-relative name", "/c:/windows", "", false, false},

		// The Win32 device names, refused on every platform so that the answer does not
		// depend on the host.
		{"the null device", "/NUL", "", false, false},
		{"the null device in lowercase", "/nul", "", false, false},
		{"the null device with an extension", "/NUL.txt", "", false, false},
		{"the console", "/con", "", false, false},
		{"a serial port", "/COM1", "", false, false},
		{"a printer port", "/lpt9", "", false, false},
		{"a console stream", "/CONIN$", "", false, false},
		{"a device in a subdirectory", "/assets/nul", "", false, false},
		{"a name that merely starts like one", "/console.log", "console.log", false, true},
		{"a name that merely contains one", "/nullable.txt", "nullable.txt", false, true},
		{"a device name with a suffix", "/com10", "com10", false, true},

		// Names Win32 would silently rewrite into another name.
		{"a trailing dot", "/index.html.", "", false, false},
		{"two trailing dots", "/index.html..", "", false, false},
		{"a trailing encoded dot", "/index.html%2e", "", false, false},

		// Dotfiles: the disclosure a static server causes most often.
		{"a repository", "/.git/config", "", false, false},
		{"an environment file", "/.env", "", false, false},
		{"a nested dotfile", "/assets/.htaccess", "", false, false},
		{"an encoded dotfile", "/%2egit/config", "", false, false},
		{"a dotfile as a directory", "/.ssh/", "", false, false},
		{"a name that merely contains a dot", "/a.b.c", "a.b.c", false, true},

		// The query, which is not part of the name.
		{"a query", "/a?b=c", "a", false, true},
		{"a query on the root", "/?x", ".", true, true},
		{"a query after a slash", "/a/?x=1", "a", true, true},
		{"a query holding a traversal", "/a?../../etc/passwd", "a", false, true},
		{"a query holding a separator", "/a?b/c", "a", false, true},
		{"an empty query", "/a?", "a", false, true},
		{"nothing but a query", "?a", "", false, false},

		// Targets that are not paths. internal/request refuses most of these before
		// this package sees them; refusing them again is what makes that a second
		// mechanism rather than an assumption.
		{"the empty target", "", "", false, false},
		{"an asterisk", "*", "", false, false},
		{"a relative path", "a/b", "", false, false},
		{"an absolute URI", "https://example.test/a", "", false, false},

		// A network-path reference, which is not one here: ":path" is a path, its first
		// segment is empty, and an empty segment names nothing. So this is "/example.test/a"
		// and not somebody else's host.
		{"a scheme-relative reference", "//example.test/a", "example.test/a", false, true},
	} {
		name, slash, ok := resolve(c.target)
		if ok != c.ok {
			t.Errorf("resolve(%q) ok = %v, want %v (%s)", c.target, ok, c.ok, c.why)
			continue
		}
		if !ok {
			continue
		}
		if name != c.name {
			t.Errorf("resolve(%q) = %q, want %q (%s)", c.target, name, c.name, c.why)
		}
		if slash != c.slash {
			t.Errorf("resolve(%q) slash = %v, want %v (%s)", c.target, slash, c.slash, c.why)
		}
	}
}

// TestResolveKeepsEveryResultInside is the claim the rest of this package rests on,
// asserted as a property of the value rather than of the path taken to it.
//
// Every target above that resolves to something at all is checked here again, against
// what the result may not be: absolute, empty, still holding a dot segment, or holding
// an octet that is a separator on some platform. A traversal that got through would have
// to leave one of those behind, and this does not care which check failed to catch it.
func TestResolveKeepsEveryResultInside(t *testing.T) {
	targets := []string{
		"/", "//", "/.", "/..", "/../..", "/a/..", "/a/../..", "/../../../etc/passwd",
		"/%2e%2e/%2e%2e/%2e%2e/etc/shadow", "/a/./../b", "/a//b", "/a/%2e%2e/b",
		"/.%2e/.%2e/x", "/%2e%2e%2f", "/....//....//x", "/a/..%2f..%2fb",
		"/x/" + strings.Repeat("../", 40) + "etc/passwd",
		strings.Repeat("/a/..", 200),
		"/" + strings.Repeat("a/", 1000) + "b",
		"/caf\u00e9/%41/a~b/a.b.c",
	}

	for _, target := range targets {
		name, _, ok := resolve(target)
		if !ok {
			continue
		}

		// Clipped, because two of these targets are four kilobytes long and a failure
		// that printed one whole would bury every other line of the report.
		short := name
		if len(short) > 60 {
			short = short[:57] + "..."
		}

		switch {
		case name == "":
			t.Errorf("resolve(%.60q) returned an empty name and ok", target)
		case strings.HasPrefix(name, "/"):
			t.Errorf("resolve(%.60q) = %q, which is absolute", target, short)
		}

		// Per segment, because "/" is what separates them and is the one octet in
		// badOctets the joined name is allowed to hold.
		inSegment := strings.ReplaceAll(badOctets, "/", "")
		for _, seg := range strings.Split(name, "/") {
			switch {
			case seg == "" || seg == ".." || (seg == "." && name != "."):
				t.Errorf("resolve(%.60q) = %q, which still holds the segment %q",
					target, short, seg)
			case strings.ContainsAny(seg, inSegment):
				t.Errorf("resolve(%.60q) = %q, whose segment %q holds one of %q",
					target, short, seg, inSegment)
			}
		}
	}
}

// TestUnescapeOctets holds the decoder to the rule that every octet is vetted whichever
// form it arrived in.
func TestUnescapeOctets(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"plain", "plain", true},
		{"%41%42", "AB", true},
		{"a%2db", "a-b", true},
		{"%7e", "~", true},
		{"%7E", "~", true},
		{"\u00ff", "\u00ff", true},

		// Every hex case, upper and lower, because a decoder that handled one case
		// would pass every test written with the other. The results are single octets
		// rather than runes: a decode produces the octet the escape named and does not
		// go looking for a character it might be part of.
		{"%ab", "\xab", true},
		{"%AB", "\xab", true},
		{"%aB", "\xab", true},

		// Truncated and invalid escapes.
		{"%", "", false},
		{"%1", "", false},
		{"a%", "", false},
		{"a%f", "", false},
		{"%g0", "", false},
		{"%0g", "", false},
		{"%%41", "", false},

		// Both digits are checked, not just the first. "%4g" read as "%40" would be "@",
		// and "%0g" read as "%00" is refused for a different reason — so a decoder that
		// stopped after the first digit would pass every other case in this table.
		{"%4g", "", false},
		{"%7g", "", false},

		// Octets no name may hold.
		{"%00", "", false},
		{"%01", "", false},
		{"%09", "", false},
		{"%0a", "", false},
		{"%0d", "", false},
		{"%20", "", false},
		{"%2f", "", false},
		{"%5c", "", false},
		{"%7f", "", false},
		{"a b", "", false},
		{"a/b", "", false},
		{`a\b`, "", false},
		{"a:b", "", false},
		{"a\x00b", "", false},
	} {
		got, ok := unescape(c.in)
		if ok != c.ok {
			t.Errorf("unescape(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("unescape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestUnhexDigits walks all 256 octets, because a hex decoder is exactly the kind of
// function whose bounds are wrong by one for a fortnight before anyone notices.
func TestUnhexDigits(t *testing.T) {
	for i := range 256 {
		c := byte(i)
		want, wantOK := byte(0), false
		switch {
		case c >= '0' && c <= '9':
			want, wantOK = c-'0', true
		case c >= 'a' && c <= 'f':
			want, wantOK = c-'a'+10, true
		case c >= 'A' && c <= 'F':
			want, wantOK = c-'A'+10, true
		}

		got, ok := unhex(c)
		if ok != wantOK {
			t.Errorf("unhex(%q) ok = %v, want %v", c, ok, wantOK)
			continue
		}
		if ok && got != want {
			t.Errorf("unhex(%q) = %d, want %d", c, got, want)
		}
	}
}

// TestNameOctetRange walks all 256 octets against the rule stated in nameOctet's
// comment, so that a change to either has to be a change to both.
func TestNameOctetRange(t *testing.T) {
	for i := range 256 {
		c := byte(i)
		want := c > 0x20 && c != 0x7f && !strings.ContainsRune(badOctets, rune(c))
		if got := nameOctet(c); got != want {
			t.Errorf("nameOctet(%#02x) = %v, want %v", c, got, want)
		}
	}

	// The rule spelled out again as the cases it is for, so that a change to the
	// expression above cannot quietly change the answer to any of these.
	for _, c := range []byte{0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x20, 0x7f, '/', '\\', ':', '*', '?', '"', '<', '>', '|'} {
		if nameOctet(c) {
			t.Errorf("nameOctet(%#02x) allows an octet no name may hold", c)
		}
	}
	for _, c := range []byte{'!', '-', '.', '0', '9', 'A', 'Z', '_', 'a', 'z', '~', 0x80, 0xff} {
		if !nameOctet(c) {
			t.Errorf("nameOctet(%#02x) refuses an octet a name may hold", c)
		}
	}
}

// mixed is a name with only its first letter capitalised, which is the spelling a device
// name is usually written in and the one a comparison that forgot to fold the case would
// let through.
func mixed(s string) string { return s[:1] + strings.ToLower(s[1:]) }

// TestReservedDeviceNames is the Win32 device list, checked case-insensitively, with and
// without extensions, and against the names that only look like devices.
func TestReservedDeviceNames(t *testing.T) {
	devices := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"CONIN$", "CONOUT$",
	}
	for _, d := range devices {
		for _, name := range []string{
			d, strings.ToLower(d), mixed(d),
			d + ".txt", strings.ToLower(d) + ".html", d + ".tar.gz",
		} {
			if !reserved(name) {
				t.Errorf("reserved(%q) = false, want true: it reaches the %s device", name, d)
			}
			if safeSegment(name) {
				t.Errorf("safeSegment(%q) = true, want false", name)
			}
		}
	}

	// Names that contain a device name without being one. A check that used
	// strings.Contains, or that compared before cutting the extension, would refuse
	// these — and "console.log" is a file a real build directory has.
	for _, name := range []string{
		"console.log", "conf", "nullable.txt", "printer.css", "com", "com0", "com10",
		"lpt", "lpt0", "auxiliary", "prnt", "conin", "aconin$", "nul2",
	} {
		if reserved(name) {
			t.Errorf("reserved(%q) = true, want false", name)
		}
		if !safeSegment(name) {
			t.Errorf("safeSegment(%q) = false, want true", name)
		}
	}
}

// TestSafeSegment is the segment rules on their own, past the ones resolve applies.
func TestSafeSegment(t *testing.T) {
	for _, c := range []struct {
		seg string
		ok  bool
	}{
		{"index.html", true},
		{"a", true},
		{"a.b.c", true},
		{"..a", false},
		{".a", false},
		{".gitignore", false},
		{"a.", false},
		{"a..", false},
		{"NUL", false},

		// A space is nameOctet's business and not this function's, so a segment with
		// one in it is safe here and unreachable through resolve. Both halves are worth
		// stating: a trailing-space rule added here would be a guard no test could
		// reach, because the octet is refused two functions earlier.
		{"a b", true},
		{"a ", true},
		{"-", true},
		{"~", true},
	} {
		if got := safeSegment(c.seg); got != c.ok {
			t.Errorf("safeSegment(%q) = %v, want %v", c.seg, got, c.ok)
		}
	}
}

// TestResolveDeepTarget is what a target at the length bound costs: nothing that grows
// faster than the target does. The assertion is only that it terminates and stays inside
// — the value of the test is that it is here at all, since a resolver with a quadratic
// step would take minutes rather than fail.
func TestResolveDeepTarget(t *testing.T) {
	for _, target := range []string{
		"/" + strings.Repeat("a/", MaxTargetLength/2),
		"/" + strings.Repeat("../", MaxTargetLength/3),
		"/" + strings.Repeat("%2e%2e/", MaxTargetLength/7),
		"/" + strings.Repeat("/", MaxTargetLength-1),
		"/" + strings.Repeat("a", MaxTargetLength-1),
	} {
		name, _, ok := resolve(target)
		if !ok {
			continue
		}
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			t.Errorf("resolve(a %d-octet target) = %q", len(target), name)
		}
	}
}

// TestWithSlash keeps the query where it was.
func TestWithSlash(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/a", "/a/"},
		{"/", "//"},
		{"/a?b=c", "/a/?b=c"},
		{"/a?", "/a/?"},
		{"/a?b=c/d", "/a/?b=c/d"},
		{"/%41", "/%41/"},
	} {
		if got := withSlash(c.in); got != c.want {
			t.Errorf("withSlash(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestJoin is the index name appended to what resolve returned, including the root.
func TestJoin(t *testing.T) {
	for _, c := range []struct{ name, elem, want string }{
		{".", "index.html", "index.html"},
		{"a", "index.html", "a/index.html"},
		{"a/b", "index.html", "a/b/index.html"},
	} {
		if got := join(c.name, c.elem); got != c.want {
			t.Errorf("join(%q, %q) = %q, want %q", c.name, c.elem, got, c.want)
		}
	}
}
