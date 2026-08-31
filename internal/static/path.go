package static

import (
	"path"
	"strings"
)

// The request target as a name inside the served directory.
//
// This file is the part of the package that can be attacked. Everything else answers a
// question about a file; this decides which file was asked for, and the whole history of
// path traversal is the history of that decision being made in a way that looked right.
//
// # Why this is not filepath.Clean on the path
//
// Two reasons, and the first is not the obvious one. A ":path" is a URI path: its
// separator is "/" on every platform, and its octets are percent-encoded, so the first
// thing that has to happen is a decode — and a decode is what turns "%2e%2e%2f" into
// "../" after any check that looked for "../" has already passed. §2.4 of RFC 3986 says
// exactly when to do it: "When a URI is dereferenced, the components and subcomponents
// significant to the scheme-specific dereferencing process (if any) must be parsed and
// separated before the percent-encoded octets within those components can be safely
// decoded, as otherwise the data may be mistaken for component delimiters". So the target
// is split on "/" first and each segment decoded afterwards, and a segment whose decoded
// form contains a separator is refused rather than joined — the alternative is a decode
// that manufactures the delimiter the split was supposed to have found.
//
// The second reason is that filepath is the host's syntax, and a server whose answers
// depend on which host it runs on is a server whose tests prove nothing about the
// deployment. On Windows "\" is a separator, ":" opens an alternate data stream, a
// trailing "." is silently dropped so that "index.html." names the same file as
// "index.html", and NUL, CON and COM1 are devices in every directory that exists.
// None of those is true on Linux. Rather than let each platform refuse its own set, the
// segment rules below refuse the union everywhere, so that the same request gets the same
// answer wherever this runs — and the platform's own refusal, in os.Root, is left as the
// backstop it should be rather than the guard it should not.
//
// # What confines the result
//
// Not this file. os.Root does, in the standard library, in the kernel: every open goes
// through a directory handle and a component that would leave the tree is refused there,
// including through a symbolic link, which no amount of string arithmetic can see. What
// this file is for is deciding what the target *means* — dot segments, encoding, the
// names that mean two things — before the answer becomes a syscall. Two independent
// mechanisms, and the outer one is not ours.

// indexFile is what a request for a directory is answered with.
//
// A directory with no index is a 404 and not a listing. A listing is a feature that
// discloses every name in a directory to anyone who guesses the directory, which is the
// wrong default for a server whose root is somebody's build output.
const indexFile = "index.html"

// MaxTargetLength bounds the ":path" this handler will look at, in octets.
//
// Not a protocol limit — §8.3.1 of RFC 9113 sets none, and internal/limits already bounds
// the header block that carries it. This is the working set of one request: a target of
// this length splits into a couple of thousand segments, each of which is decoded and
// vetted, and the point of a bound is that the number is a constant rather than something
// the peer chooses. 4 KiB is roughly twice the longest URL the major browsers will
// generate and far above anything a link contains.
//
// Kept here rather than in internal/limits, which is the frame layer's bounds and is
// enforced by the frame reader. Nothing outside this package has any use for this number.
const MaxTargetLength = 4096

// resolve turns a ":path" into a slash-separated name inside the served directory.
//
// The name is relative and never begins with a separator; a target that resolves to the
// directory itself is ".", which is the name os.Root uses for it. slash reports whether
// the target ended in "/", which is what distinguishes a request for a directory from a
// request for the thing inside it — see Handler.serve's redirect. ok is false when the
// target names something no file can be, and every one of those is answered as a missing
// file: the code covers both cases, since per §15.5.5 of RFC 9110 the origin server "did
// not find a current representation for the target resource or is not willing to disclose
// that one exists", and telling a prober which of its guesses were merely absent is
// disclosure.
func resolve(target string) (name string, slash, ok bool) {
	// The query is not part of the name. It is not part of the path either — §3.4 of RFC
	// 3986 makes it a separate component that begins at the first "?" — so this is where
	// the path component ends, and a "?" further along belongs to the query and not to
	// this decision.
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}

	// An absolute path or nothing. ":path" is already held to this by internal/request for
	// an "http" or "https" request, and is not for any other scheme; a target that is
	// "*", or a whole URI, or empty, names no file here.
	if target == "" || target[0] != '/' {
		return "", false, false
	}

	raw := strings.Split(target[1:], "/")
	slash = raw[len(raw)-1] == ""

	// §5.2.4's remove_dot_segments, on the decoded segments, and applied even though this
	// target is already absolute rather than a reference. Which implementations get that
	// wrong, and how, per §6.2.2.3 of RFC 3986: "some deployed implementations incorrectly
	// assume that reference resolution is not necessary when the reference is already a URI
	// and thus fail to remove dot-segments when they occur in non-relative paths".
	//
	// A ".." with nothing to pop is dropped rather than refused, which is what §5.2.4 does
	// and is the reason the output cannot escape: after this loop no segment is "..", so
	// there is nothing left for a join to interpret. Refusing instead would be a defensible
	// policy and a worse one — it makes the safety of the result depend on a check having
	// run, where discarding makes it a property of the value.
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		s, good := unescape(seg)
		if !good {
			return "", false, false
		}
		switch s {
		case "", ".":
			// An empty segment is the trailing slash, or a "//" in the middle, and neither
			// names anything: "/a//b" and "/a/b" are the same path with the same meaning.
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		if !safeSegment(s) {
			return "", false, false
		}
		out = append(out, s)
	}

	if len(out) == 0 {
		return ".", slash, true
	}
	return strings.Join(out, "/"), slash, true
}

// unescape decodes one path segment's percent-encoding, or reports that it cannot be a
// file name.
//
// Every octet is held to the same rule whether it arrived raw or encoded, which is the
// only way the two forms of a target get the same answer. internal/request has already
// refused the control octets in the raw path — it has to, because they are what smuggling
// is made of — and a decode reintroduces exactly that possibility, so the check is here
// again rather than trusted from there.
func unescape(seg string) (string, bool) {
	// Nothing to decode is the common case and every octet has already been vetted by the
	// loop's own rule, so it still goes through the check and not around it.
	var b strings.Builder
	b.Grow(len(seg))

	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c != '%' {
			if !nameOctet(c) {
				return "", false
			}
			b.WriteByte(c)
			continue
		}

		// "%" is the one octet that cannot be data: §2.1 of RFC 3986 makes it the
		// indicator, so a "%" not followed by two hex digits is not a name with a percent
		// in it, it is a truncated or invented encoding. Refused rather than passed
		// through as a literal, which is how one implementation's "%2" becomes another's
		// escape when the target is forwarded.
		if i+2 >= len(seg) {
			return "", false
		}
		hi, ok1 := unhex(seg[i+1])
		lo, ok2 := unhex(seg[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		if d := hi<<4 | lo; nameOctet(d) {
			b.WriteByte(d)
		} else {
			return "", false
		}
		i += 2
	}
	return b.String(), true
}

// unhex is one hex digit's value.
func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// badOctets are the octets a segment may not contain, decoded or otherwise.
//
// The two separators first, and they are the ones that matter: a segment holding "/" or
// "\" is a segment that would become two, after the split that was supposed to have found
// them. That is the "%2f" family of traversals, and it is refused rather than decoded for
// the reason §2.4 of RFC 3986 gives.
//
// Then the octets Win32 refuses in a name. ":" is the alternate-data-stream separator, so
// "index.html:hidden" and "file.txt::$DATA" are two more names for one file and one of
// them skips an extension check; the rest are simply invalid there. Refusing them on every
// platform costs the ability to serve a file whose name contains a colon on Linux, which
// is not a file worth the difference between two platforms' answers.
const badOctets = `/\:*?"<>|`

// nameOctet reports whether c may appear in a file name.
//
// Everything below "!" goes: NUL, which truncates a name in every C library the syscall
// passes through; CR and LF, which are how a field value becomes two; and the space,
// which Win32 strips from the end of a name so that "a " and "a" are one file. DEL for
// the same reason as the controls. Above 0x7f is deliberately allowed — a UTF-8 file name
// is a file name, and curl sends one raw.
func nameOctet(c byte) bool {
	return c > 0x20 && c != 0x7f && strings.IndexByte(badOctets, c) < 0
}

// safeSegment reports whether a decoded segment may be looked up.
//
// Called after the dot segments have been resolved away, so "." and ".." never reach it
// and the rules below are about names rather than about navigation.
func safeSegment(s string) bool {
	// A name beginning with "." is not served. This is policy rather than protocol, and it
	// is the policy that keeps .git, .env, .ssh and .htaccess out of a response when a
	// build directory turns out to have one in it — the disclosure that a static server
	// causes most often, and one nothing else in this package would notice. The cost is
	// that a deployment needing /.well-known would have to say so; there is nothing in
	// this server that generates one.
	if s[0] == '.' {
		return false
	}

	// A trailing "." is stripped by Win32 before the file is opened, which makes
	// "index.html." a second name for "index.html" that no extension check would agree
	// about — mediaType would call it octet-stream and the filesystem would serve HTML.
	// Two names for one representation is also a cache-poisoning shape, and neither reason
	// depends on the platform, so both platforms refuse it.
	if s[len(s)-1] == '.' {
		return false
	}

	return !reserved(s)
}

// reservedNames are the Win32 device names, which exist in every directory.
//
// Opening one is not a file access at all: it is a handle on the console, a printer port
// or the null device, and it can block, succeed emptily, or hang a request on a serial
// port that nothing is attached to. os.Root refuses them when GOOS is windows and says so
// in its own documentation, which makes this list the *other* half of the promise — the
// half that makes a Linux directory containing a file called "NUL" answer the same way.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	"CONIN$": true, "CONOUT$": true,
}

// reserved reports whether a segment names a Win32 device.
//
// The extension is cut off first, because the device is reached through it too: "NUL.txt"
// is the null device and not a text file, and a check that compared the whole segment
// would pass every one of them. Compared upper-cased, because the names are matched
// case-insensitively there — "nul", "Nul" and "NUL" are one device.
func reserved(s string) bool {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	return reservedNames[strings.ToUpper(s)]
}

// mediaType is the content-type for a name, from its extension.
//
// Unknown means application/octet-stream, which §8.3 of RFC 9110 names as what a
// recipient may assume when the field is absent — so this is the same answer, said out
// loud. Saying it matters: a browser handed content with no type of its own sniffs it,
// and a file the server has no opinion about is exactly the file whose content should not
// be allowed to choose how it is interpreted.
func mediaType(name string) string {
	if t, ok := mediaTypes[strings.ToLower(path.Ext(name))]; ok {
		return t
	}
	return octetStream
}
