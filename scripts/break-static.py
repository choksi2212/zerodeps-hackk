"""Deliberately break internal/static, one guard at a time, and report which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Three files, because the package is three jobs and only the first of them is dangerous.
path.go decides which file a request target names, which is the whole attack surface:
every path-traversal bug in the history of static file serving is that decision made in a
way that looked right. media.go is the table that says what a file is, where being wrong
in one direction is a download and in the other is script running in the origin. static.go
is the response itself -- the statuses, the fields, and the octets.

  Most of path.go's guards are checked twice on purpose, and the campaign is where that
  pays off. resolve refuses an octet whether it arrived raw or percent-encoded, so removing
  either check leaves the other passing every test written against the form it handles: the
  pair of breaks on nameOctet's two callers is there to prove neither is redundant. The
  same shape appears in the two halves of badOctets, broken separately because the
  separators and the Win32 octets are two different arguments for one constant, and in the
  device-name check, whose case folding, extension cut and membership test look like one
  line and are three guards.

  Five of the guards below are what keeps an index in range, so removing one is a panic
  rather than a wrong answer: resolve's empty-target half is what keeps target[0]
  addressable, safeSegment reads s[0] and so cannot be handed the empty segment resolve is
  supposed to have dropped, the ".." arm pops a slice the length check is what keeps
  non-empty, unescape's bound is what keeps seg[i+2] addressable, and the second open's
  error is what keeps a nil FileInfo out of info.Mode(). All five are reported as ordinary
  failures rather than as the harness's crash outcome, which is the result worth having:
  the panic happens inside the test that exercises the guard, so the report names that test
  and the panic together instead of leaving a dead binary and nothing to attribute it to.

  media.go is data, and a campaign over data has to pick representatives rather than walk
  thirty-four entries. Eight are here: the four shapes a mistyped entry actually has -- a
  key without its dot, a key not folded to lower case, a value with no subtype, a text type
  with no charset -- the two whose being wrong is a security bug rather than a display bug,
  .html served as text and .txt served as HTML, a charset on an image, and an entry that
  states the default explicitly. The rest of the table is held to those same properties by
  TestMediaTypeTable, which is what makes eight enough.

  Four assertions were added to static_test.go while this campaign was being written,
  because four guards had no test that could fail. Three were constants the tests derived
  from -- MaxTargetLength, allowedMethods, and the frame count of a bodyless response --
  where widening or narrowing the constant rescaled every assertion built on it and passed.
  The fourth was the frame that ends a 404, which no case in TestServeReturnsTheWriteError
  reached. A bound the test computes from the bound is not a tested bound, and that is the
  single most useful thing this campaign found.

Four guards are not in this campaign, and all four absences are deliberate.

  open's stat is taken on the handle rather than on the name, which is what makes the size,
  the mode and the content one file. Replacing f.Stat() with h.root.Stat(name) reintroduces
  the double lookup, and the window it opens is between two syscalls: seeing it means
  replacing the file with a symbolic link inside that window, which is a race the test
  would have to win rather than an assertion it could make. There is no seam to do it
  through and no honest test to name here.

  unescape's first hex digit is checked and the check cannot be observed. unhex returns
  (0, false) for anything that is not a digit, so a bad first digit makes the decoded octet
  the second nibble alone -- at most 0x0f, which nameOctet already refuses along with
  everything below 0x21. Removing !ok1 changes no answer for any input. It stays in the
  code because it states the rule the decoder follows instead of leaning on another
  function's lower bound, and it stays out of this campaign because a break nothing can
  observe is not a hole in the suite. The second digit is a different matter and is broken
  below: "%4z" read as "%40" is "@", which is a perfectly good file name.

  The f.Close() before the redirect is not broken into a leaked handle. On Windows the
  operating system refuses to remove a directory something still has open, so t.TempDir's
  cleanup would fail and the failure would be reported against whichever test used one; on
  Linux nothing would notice at all. A break whose outcome depends on the host is worse
  than no break, because it reads as a tested guard on one machine only.

  The copy buffer's pool cannot be turned into one shared buffer by a single edit -- the
  field and the Get are two hunks, and a break is one. What the pool has to be is asserted
  by TestServeIsConcurrencySafe, whose goroutines over eight files would show a shared
  buffer as another file's octets and which the race detector names outright. This harness
  does not pass -race; that test is run with it by the suite.

Run from the repository root. Restores all three files on the way out, including on error.
"""

import breakage

SRC = [
    "internal/static/path.go",
    "internal/static/media.go",
    "internal/static/static.go",
]
PKG = "./internal/static/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- path.go: what the target is, before it is a name -------------------
    (
        "the query is part of the name, so /index.html?v=2 is a file nobody has",
        """	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}""",
        """	if i := strings.IndexByte(target, '?'); i >= 0 {
		_ = i
	}""",
        ["TestResolveTargets", "TestServeQueryIsNotPartOfTheName"],
    ),
    (
        "a target that is not an absolute path is resolved anyway",
        '''	if target == "" || target[0] != '/' {
		return "", false, false
	}''',
        '''	if target == "" {
		return "", false, false
	}''',
        ["TestResolveTargets"],
    ),
    (
        "the empty target reaches target[0]",
        '''	if target == "" || target[0] != '/' {''',
        """	if target[0] != '/' {""",
        ["TestResolveTargets"],
    ),
    (
        "the trailing slash is looked for at the front of the target",
        '''	slash = raw[len(raw)-1] == ""''',
        '''	slash = raw[0] == ""''',
        ["TestResolveTargets", "TestServeDirectoryIndex"],
    ),
    (
        "an empty segment is looked up instead of dropped, and safeSegment reads s[0]",
        '''		case "", ".":''',
        '''		case ".":''',
        ["TestResolveTargets"],
    ),
    (
        "a dot segment is looked up as a name, which the dotfile rule then refuses",
        '''		case "", ".":
			// An empty segment is the trailing slash, or a "//" in the middle, and neither
			// names anything: "/a//b" and "/a/b" are the same path with the same meaning.
			continue''',
        '''		case "":
			continue''',
        ["TestResolveTargets", "TestServeDirectoryRedirects"],
    ),
    (
        "a pop with nothing to pop takes a slice past its own start",
        '''		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue''',
        '''		case "..":
			out = out[:len(out)-1]
			continue''',
        ["TestResolveTargets", "TestResolveKeepsEveryResultInside"],
    ),
    (
        "dot segments are never resolved, so .. is a name the dotfile rule is what refuses",
        '''		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}''',
        """		}""",
        ["TestResolveTargets", "TestServeDirectoryRedirects"],
    ),
    (
        "the segments are never decoded, so %2e%2e is a directory name",
        """		s, good := unescape(seg)""",
        """		s, good := seg, true""",
        ["TestResolveTargets", "TestServeRootIndex"],
    ),
    (
        "the segment rules are never applied, so .env is a file this server serves",
        """		if !safeSegment(s) {""",
        """		if false {""",
        ["TestResolveTargets", "TestServeDotfilesAreNotServed"],
    ),
    (
        "a raw octet is not vetted, only a decoded one",
        '''		if c != '%' {
			if !nameOctet(c) {
				return "", false
			}
			b.WriteByte(c)
			continue
		}''',
        """		if c != '%' {
			b.WriteByte(c)
			continue
		}""",
        ["TestResolveTargets", "TestUnescapeOctets"],
    ),
    (
        "a decoded octet is not vetted, only a raw one, so %2f is the separator the split missed",
        '''		if d := hi<<4 | lo; nameOctet(d) {
			b.WriteByte(d)
		} else {
			return "", false
		}''',
        """		b.WriteByte(hi<<4 | lo)""",
        ["TestResolveTargets", "TestUnescapeOctets"],
    ),
    (
        "the truncated-escape bound is off by one, so a percent near the end indexes past it",
        """		if i+2 >= len(seg) {""",
        """		if i+2 > len(seg) {""",
        ["TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "only the first hex digit is checked, so %4z decodes to @",
        '''		if !ok1 || !ok2 {
			return "", false
		}''',
        '''		_ = ok2
		if !ok1 {
			return "", false
		}''',
        ["TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "a decoded escape's own digits are read again as data",
        """		i += 2
	}
	return b.String(), true""",
        """	}
	return b.String(), true""",
        ["TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "an upper-case escape does not decode, so %2E%2E is a name and %2e%2e is a pop",
        """	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}""",
        """	}""",
        ["TestUnhexDigits", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "the decimal digits stop at 8",
        """	case '0' <= c && c <= '9':""",
        """	case '0' <= c && c < '9':""",
        ["TestUnhexDigits"],
    ),
    (
        "the lower-case hex digits stop at e",
        """	case 'a' <= c && c <= 'f':""",
        """	case 'a' <= c && c <= 'e':""",
        ["TestUnhexDigits"],
    ),
    (
        "a segment may hold the separators, which is the whole %2f family",
        """const badOctets = `/\\:*?"<>|`""",
        """const badOctets = `:*?"<>|`""",
        ["TestNameOctetRange", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "a segment may hold the octets Win32 refuses, which is one file with two names",
        """const badOctets = `/\\:*?"<>|`""",
        """const badOctets = `/\\`""",
        ["TestNameOctetRange", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "a name may end in the space Win32 strips from it",
        """	return c > 0x20 && c != 0x7f && strings.IndexByte(badOctets, c) < 0""",
        """	return c >= 0x20 && c != 0x7f && strings.IndexByte(badOctets, c) < 0""",
        ["TestNameOctetRange", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "DEL is an ordinary octet",
        """	return c > 0x20 && c != 0x7f && strings.IndexByte(badOctets, c) < 0""",
        """	return c > 0x20 && strings.IndexByte(badOctets, c) < 0""",
        ["TestNameOctetRange", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "the octet list is never consulted, only the control range",
        """	return c > 0x20 && c != 0x7f && strings.IndexByte(badOctets, c) < 0""",
        """	return c > 0x20 && c != 0x7f""",
        ["TestNameOctetRange", "TestUnescapeOctets", "TestResolveTargets"],
    ),
    (
        "the segment list starts full of empty strings, so every name comes out absolute",
        """	out := make([]string, 0, len(raw))""",
        """	out := make([]string, len(raw))""",
        ["TestResolveTargets", "TestResolveKeepsEveryResultInside"],
    ),
    (
        "the served directory itself is named by the empty string rather than by dot",
        '''	if len(out) == 0 {
		return ".", slash, true
	}''',
        '''	if len(out) == 0 {
		return "", slash, true
	}''',
        [
            "TestResolveTargets",
            "TestResolveKeepsEveryResultInside",
            "TestServeRootIndex",
        ],
    ),
    (
        "a name may end in the dot Win32 drops, so index.html. is a second name for one file",
        """	if s[len(s)-1] == '.' {
		return false
	}

	return !reserved(s)""",
        """	return !reserved(s)""",
        ["TestSafeSegment", "TestResolveTargets"],
    ),
    (
        "dotfiles are served, which is the disclosure a static server causes most often",
        """	if s[0] == '.' {
		return false
	}""",
        """	if s[0] == 0 {
		return false
	}""",
        ["TestSafeSegment", "TestResolveTargets", "TestServeDotfilesAreNotServed"],
    ),
    (
        "the device list is never consulted",
        """	return !reserved(s)""",
        """	return true""",
        ["TestSafeSegment", "TestReservedDeviceNames", "TestResolveTargets"],
    ),
    (
        "a device is reached through an extension, since NUL.txt is not a text file",
        """	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	return reservedNames[strings.ToUpper(s)]""",
        """	return reservedNames[strings.ToUpper(s)]""",
        ["TestReservedDeviceNames", "TestResolveTargets"],
    ),
    (
        "the extension is cut at the last dot, so NUL.tar.gz reaches the device",
        """	if i := strings.IndexByte(s, '.'); i >= 0 {""",
        """	if i := strings.LastIndexByte(s, '.'); i >= 0 {""",
        ["TestReservedDeviceNames"],
    ),
    (
        "the device names are matched case-sensitively, and Win32 does not",
        """	return reservedNames[strings.ToUpper(s)]""",
        """	return reservedNames[s]""",
        ["TestReservedDeviceNames", "TestResolveTargets"],
    ),
    (
        "the console streams are not devices",
        '''	"CONIN$": true, "CONOUT$": true,
}''',
        """}""",
        ["TestReservedDeviceNames", "TestResolveTargets"],
    ),
    (
        "the target bound is widened, which every assertion derived from it would have rescaled",
        """const MaxTargetLength = 4096""",
        """const MaxTargetLength = 8192""",
        ["TestServeTargetTooLong"],
    ),
    (
        "a directory is answered with an index nobody generates",
        '''const indexFile = "index.html"''',
        '''const indexFile = "index.htm"''',
        ["TestServeRootIndex", "TestServeDirectoryIndex"],
    ),
    (
        "the extension is not folded, so INDEX.HTML is an octet stream",
        """	if t, ok := mediaTypes[strings.ToLower(path.Ext(name))]; ok {""",
        """	if t, ok := mediaTypes[path.Ext(name)]; ok {""",
        ["TestMediaTypeForName"],
    ),
    (
        "the whole file name is looked up instead of its extension",
        """	if t, ok := mediaTypes[strings.ToLower(path.Ext(name))]; ok {""",
        """	if t, ok := mediaTypes[strings.ToLower(path.Base(name))]; ok {""",
        ["TestMediaTypeForName", "TestServeFile"],
    ),
    (
        "an unknown extension is text rather than an octet stream, so its content is sniffed",
        """	return octetStream""",
        """	return textPlain""",
        ["TestMediaTypeForName", "TestServeUnknownTypeIsOctetStream"],
    ),
    (
        "the lookup's answer is used when it failed and dropped when it succeeded",
        """	if t, ok := mediaTypes[strings.ToLower(path.Ext(name))]; ok {
		return t
	}""",
        """	if t, ok := mediaTypes[strings.ToLower(path.Ext(name))]; !ok {
		return t
	}""",
        ["TestMediaTypeForName", "TestServeFile"],
    ),

    # --- media.go: the table ------------------------------------------------
    (
        "HTML is served as text, so every page is a wall of source",
        '''	".html":  "text/html; charset=utf-8",''',
        '''	".html":  "text/plain; charset=utf-8",''',
        ["TestMediaTypeForName", "TestMediaTypeHTMLIsDeliberate", "TestServeFile"],
    ),
    (
        "a text file is served as HTML, which is the whole shape of a stored-XSS bug",
        """	".txt": textPlain,""",
        '''	".txt": "text/html; charset=utf-8",''',
        ["TestMediaTypeForName", "TestMediaTypeHTMLIsDeliberate"],
    ),
    (
        "an image carries a charset, which is a parameter the format has no use for",
        '''	".png":  "image/png",''',
        '''	".png":  "image/png; charset=utf-8",''',
        ["TestMediaTypeTable", "TestMediaTypeForName"],
    ),
    (
        "a text type carries no charset, so the browser guesses an encoding",
        '''	".css":  "text/css; charset=utf-8",''',
        '''	".css":  "text/css",''',
        ["TestMediaTypeTable", "TestMediaTypeForName"],
    ),
    (
        "an entry states the default explicitly, which is what an absent key already means",
        '''	".zip": "application/zip",''',
        """	".zip": octetStream,""",
        ["TestMediaTypeDefaultIsNotInTheTable"],
    ),
    (
        "a key is written without the dot path.Ext returns",
        '''	".gz":  "application/gzip",''',
        '''	"gz":  "application/gzip",''',
        ["TestMediaTypeTable", "TestMediaTypeForName"],
    ),
    (
        "a key is written in upper case, which the folded lookup can never find",
        '''	".jpg":  "image/jpeg",''',
        '''	".JPG":  "image/jpeg",''',
        ["TestMediaTypeTable", "TestMediaTypeForName"],
    ),
    (
        "a value is a type with no subtype",
        '''	".wasm": "application/wasm",''',
        '''	".wasm": "application",''',
        ["TestMediaTypeTable", "TestMediaTypeForName"],
    ),

    # --- static.go: the method, the bound, the redirect ---------------------
    (
        "every method is served, so a POST writes nothing and gets a file back",
        '''	if r.Method != methodGet && r.Method != methodHead {
		return h.answer(w, r, status405, textPlain, body405,
			h2.Field{Name: "allow", Value: allowedMethods})
	}

	if len(r.Path) > MaxTargetLength {''',
        """	if len(r.Path) > MaxTargetLength {""",
        ["TestServeMethodNotAllowed"],
    ),
    (
        "HEAD is not one of the methods this handler answers",
        """	if r.Method != methodGet && r.Method != methodHead {""",
        """	if r.Method != methodGet {""",
        [
            "TestHeadMatchesGet",
            "TestHeadContentLengthIsTheGetLength",
            "TestServeMethodNotAllowed",
            "TestServeTraversalNeverEscapes",
        ],
    ),
    (
        "the 405 does not say which methods are allowed",
        '''		return h.answer(w, r, status405, textPlain, body405,
			h2.Field{Name: "allow", Value: allowedMethods})''',
        """		return h.answer(w, r, status405, textPlain, body405)""",
        ["TestServeMethodNotAllowed"],
    ),
    (
        "the allow field promises one method where two are answered",
        '''	allowedMethods = "GET, HEAD"''',
        '''	allowedMethods = "GET"''',
        ["TestServeMethodNotAllowed"],
    ),
    (
        "a target of any length is decoded and vetted segment by segment",
        """	if len(r.Path) > MaxTargetLength {
		return h.answer(w, r, status414, textPlain, body414)
	}

	name, slash, ok := resolve(r.Path)""",
        """	name, slash, ok := resolve(r.Path)""",
        ["TestServeTargetTooLong"],
    ),
    (
        "the target bound is off by one, so a target at the limit is refused",
        """	if len(r.Path) > MaxTargetLength {""",
        """	if len(r.Path) >= MaxTargetLength {""",
        ["TestServeTargetTooLong"],
    ),
    (
        "a directory is never recognised as one, so every index is a 404",
        """	if info.IsDir() {""",
        """	if info.IsDir() && false {""",
        [
            "TestServeRootIndex",
            "TestServeDirectoryRedirects",
            "TestServeDirectoryIndex",
        ],
    ),
    (
        "a directory without its slash serves the index, so every relative link in it breaks",
        """		if !slash {""",
        """		if !slash && false {""",
        ["TestServeDirectoryRedirects"],
    ),
    (
        "the redirect is sent to the target that already has its slash",
        """		if !slash {""",
        """		if slash {""",
        ["TestServeDirectoryRedirects", "TestServeDirectoryIndex"],
    ),
    (
        "the location is the resolved name rather than the peer's own target",
        '''				h2.Field{Name: "location", Value: withSlash(r.Path)})''',
        '''				h2.Field{Name: "location", Value: withSlash(name)})''',
        ["TestServeDirectoryRedirects"],
    ),
    (
        "the redirect's slash lands inside the query's value",
        """	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i] + "/" + target[i:]
	}""",
        """	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target + "/"
	}""",
        ["TestWithSlash", "TestServeDirectoryRedirects"],
    ),
    (
        "the redirect is to the target it was sent for",
        '''	return target + "/"''',
        """	return target""",
        ["TestWithSlash", "TestServeDirectoryRedirects"],
    ),
    (
        "the served directory is joined as a segment of its own name",
        '''	if name == "." {
		return elem
	}''',
        """""",
        ["TestJoin"],
    ),
    (
        "the index name is never appended, so a directory is opened as the response",
        """		name = join(name, indexFile)
		if f, info, err = h.open(name); err != nil {""",
        """		if f, info, err = h.open(name); err != nil {""",
        ["TestServeRootIndex", "TestServeDirectoryIndex"],
    ),
    (
        "a missing index leaves a nil FileInfo to be read",
        """		if f, info, err = h.open(name); err != nil {""",
        """		if f, info, err = h.open(name); false {""",
        ["TestServeDirectoryWithoutIndex"],
    ),
    (
        "anything that is not a regular file is sent as one",
        """	if !info.Mode().IsRegular() {
		return h.answer(w, r, status404, textPlain, body404)
	}

	return h.file(w, r, f, info.Size(), mediaType(name))""",
        """	return h.file(w, r, f, info.Size(), mediaType(name))""",
        ["TestServeIndexThatIsADirectory"],
    ),

    # --- static.go: the content ---------------------------------------------
    (
        "a HEAD carries the file's content",
        """	if r.Method == methodHead || size == 0 {
		return w.WriteBodylessHeader(fields)
	}""",
        """	if size == 0 {
		return w.WriteBodylessHeader(fields)
	}""",
        ["TestHeadMatchesGet"],
    ),
    (
        "an empty file is a header section and a frame saying there is nothing to carry",
        """	if r.Method == methodHead || size == 0 {
		return w.WriteBodylessHeader(fields)
	}""",
        """	if r.Method == methodHead {
		return w.WriteBodylessHeader(fields)
	}""",
        ["TestServeEmptyFile"],
    ),
    (
        "a HEAD's header section does not end the stream, so the peer waits for content",
        """	if r.Method == methodHead || size == 0 {
		return w.WriteBodylessHeader(fields)
	}""",
        """	if r.Method == methodHead || size == 0 {
		return w.WriteHeader(fields)
	}""",
        ["TestHeadMatchesGet", "TestServeEmptyFile"],
    ),
    (
        "a HEAD carries an error response's content",
        '''	if r.Method == methodHead || body == "" {
		return w.WriteBodylessHeader(fields)
	}''',
        '''	if body == "" {
		return w.WriteBodylessHeader(fields)
	}''',
        ["TestHeadMatchesGet"],
    ),
    (
        "a response with no content is two frames, the second one saying so",
        '''	if r.Method == methodHead || body == "" {
		return w.WriteBodylessHeader(fields)
	}''',
        """	if r.Method == methodHead {
		return w.WriteBodylessHeader(fields)
	}""",
        ["TestServeDirectoryRedirects"],
    ),
    (
        "a redirect's header section does not end the stream",
        '''	if r.Method == methodHead || body == "" {
		return w.WriteBodylessHeader(fields)
	}''',
        '''	if r.Method == methodHead || body == "" {
		return w.WriteHeader(fields)
	}''',
        ["TestServeDirectoryRedirects", "TestHeadMatchesGet"],
    ),
    (
        "the copy is not bounded by the length that was declared",
        """	n, err := io.CopyBuffer(w, io.LimitReader(f, size), *buf)""",
        """	n, err := io.CopyBuffer(w, f, *buf)""",
        ["TestFileGrewIsSentAsDeclared"],
    ),
    (
        "the copy buffer is not the frame size, so the peer's window is a frame count",
        """			b := make([]byte, limits.MaxFrameSize)""",
        """			b := make([]byte, limits.MaxFrameSize/16)""",
        ["TestServeFrameSizeIsTheCopyBuffer", "TestServeLargeFileIsSplitByFrameSize"],
    ),
    (
        "a file that shrank under the response is reported as having been sent",
        """	if n != size {
		return errFileChanged
	}
	return nil
}""",
        """	_ = n
	return nil
}""",
        ["TestFileShrankEndsTheStreamFirst"],
    ),
    (
        "the truncation is reported before the stream ends, so the peer waits for the difference",
        """	if err := w.Close(); err != nil {
		return err
	}
	if n != size {
		return errFileChanged
	}""",
        """	if n != size {
		return errFileChanged
	}
	if err := w.Close(); err != nil {
		return err
	}""",
        ["TestFileShrankEndsTheStreamFirst"],
    ),
    (
        "a failed DATA frame is reported as a response that went out",
        """	if err != nil {
		return err
	}""",
        """	if err != nil {
		return nil
	}""",
        ["TestServeReturnsTheWriteError"],
    ),
    (
        "the frame that ends a file's stream is not checked",
        """	if err := w.Close(); err != nil {
		return err
	}
	if n != size {""",
        """	_ = w.Close()
	if n != size {""",
        ["TestServeReturnsTheWriteError"],
    ),
    (
        "an error response never ends its stream",
        """	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()""",
        """	_, err := io.WriteString(w, body)
	return err""",
        ["TestServeMissingFile", "TestServeMethodNotAllowed"],
    ),
    (
        "the frame that ends an error response is not checked",
        """	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()""",
        """	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	w.Close()
	return nil""",
        ["TestServeReturnsTheWriteError"],
    ),

    # --- static.go: the fields ----------------------------------------------
    (
        "the fields a status brings with it are dropped, so no 405 says allow and no 301 where",
        """	fields := append(h.fields(status, kind, int64(len(body))), extra...)""",
        """	fields := h.fields(status, kind, int64(len(body)))""",
        ["TestServeMethodNotAllowed", "TestServeDirectoryRedirects"],
    ),
    (
        "an error response declares no content and sends some",
        """	fields := append(h.fields(status, kind, int64(len(body))), extra...)""",
        """	fields := append(h.fields(status, kind, 0), extra...)""",
        ["TestContentLengthIsTheContent", "TestServeMissingFile"],
    ),
    (
        "a file's length is not the file's length",
        """	fields := h.fields(status200, kind, size)""",
        """	fields := h.fields(status200, kind, 0)""",
        [
            "TestContentLengthIsTheContent",
            "TestServeFile",
            "TestHeadContentLengthIsTheGetLength",
        ],
    ),
    (
        "a response with no content type sends an empty one",
        '''	if kind != "" {
		fields = append(fields, h2.Field{Name: "content-type", Value: kind})
	}''',
        """	fields = append(fields, h2.Field{Name: "content-type", Value: kind})""",
        ["TestServeDirectoryRedirects"],
    ),
    (
        "the status comes after a field line, which 8.3 puts it before",
        '''	fields = append(fields,
		h2.Field{Name: ":status", Value: status},
		h2.Field{Name: "content-length", Value: strconv.FormatInt(length, 10)},
	)''',
        '''	fields = append(fields,
		h2.Field{Name: "content-length", Value: strconv.FormatInt(length, 10)},
		h2.Field{Name: ":status", Value: status},
	)''',
        ["TestFieldsAreLowerCaseAndPseudoFirst", "TestServeFile"],
    ),
    (
        "nothing declares how long the content is, because the field is misspelled",
        '''		h2.Field{Name: "content-length", Value: strconv.FormatInt(length, 10)},''',
        '''		h2.Field{Name: "content-len", Value: strconv.FormatInt(length, 10)},''',
        [
            "TestContentLengthIsTheContent",
            "TestServeFile",
            "TestHeadContentLengthIsTheGetLength",
        ],
    ),
    (
        "no response carries a date, which 6.6.1 requires of all three statuses sent here",
        '''	fields = append(fields,
		h2.Field{Name: "date", Value: h.now().UTC().Format(imfFixdate)},
		h2.Field{Name: "server", Value: serverName},
	)''',
        '''	fields = append(fields,
		h2.Field{Name: "server", Value: serverName},
	)''',
        ["TestDateIsGMT", "TestDateFromTheRealClock", "TestServeFile"],
    ),
    (
        "the date is the host's local time under a field whose format ends in GMT",
        '''		h2.Field{Name: "date", Value: h.now().UTC().Format(imfFixdate)},''',
        '''		h2.Field{Name: "date", Value: h.now().Format(imfFixdate)},''',
        ["TestDateIsGMT"],
    ),
    (
        "the date's day is not padded, so it is a narrower field for nine days of every month",
        '''const imfFixdate = "Mon, 02 Jan 2006 15:04:05 GMT"''',
        '''const imfFixdate = "Mon, 2 Jan 2006 15:04:05 GMT"''',
        ["TestDateIsGMT", "TestServeFile"],
    ),
    (
        "the date names whichever zone it was formatted in rather than GMT",
        '''const imfFixdate = "Mon, 02 Jan 2006 15:04:05 GMT"''',
        '''const imfFixdate = "Mon, 02 Jan 2006 15:04:05 MST"''',
        ["TestDateIsGMT", "TestServeFile"],
    ),
    (
        "nothing identifies the server in a packet capture",
        '''		h2.Field{Name: "server", Value: serverName},
	)
	return fields''',
        """	)
	return fields""",
        ["TestServeFile", "TestServeMissingFile"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
