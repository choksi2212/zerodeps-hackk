package static

import (
	"strings"
	"testing"
)

// TestMediaTypeForName is the table as it is reached: through a file name, with the
// extension cut off by path.Ext and folded.
func TestMediaTypeForName(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"index.html", "text/html; charset=utf-8"},
		{"index.htm", "text/html; charset=utf-8"},
		{"app.js", "text/javascript; charset=utf-8"},
		{"app.mjs", "text/javascript; charset=utf-8"},
		{"main.css", "text/css; charset=utf-8"},
		{"data.json", "application/json"},
		{"app.js.map", "application/json"},
		{"logo.svg", "image/svg+xml"},
		{"photo.jpeg", "image/jpeg"},
		{"photo.jpg", "image/jpeg"},
		{"favicon.ico", "image/vnd.microsoft.icon"},
		{"font.woff2", "font/woff2"},
		{"vm.wasm", "application/wasm"},
		{"notes.md", "text/markdown; charset=utf-8"},
		{"notes.txt", textPlain},

		// Case folded, because a file called INDEX.HTML is an HTML file and a table
		// keyed only by the lower-case spelling would call it octet-stream.
		{"INDEX.HTML", "text/html; charset=utf-8"},
		{"Photo.JPG", "image/jpeg"},
		{"App.Js", "text/javascript; charset=utf-8"},

		// The last extension wins, which is path.Ext's rule and the right one: a
		// .tar.gz is a gzip stream, and what is inside it is not this field's business.
		{"archive.tar.gz", "application/gzip"},
		{"archive.tar", "application/x-tar"},
		{"a.b.c.html", "text/html; charset=utf-8"},

		// Nothing this table knows about, which is every other file in the world.
		{"README", octetStream},
		{"Makefile", octetStream},
		{"a", octetStream},
		{"a.", octetStream},
		{"a.unknown", octetStream},
		{"a.exe", octetStream},
		{"", octetStream},
		{".", octetStream},

		// The extension is the final slash-separated element's, so a dot in a
		// directory name is not one. Without this, "a.html/README" would be HTML.
		{"a.html/README", octetStream},
		{"a.txt/b.png", "image/png"},
	} {
		if got := mediaType(c.name); got != c.want {
			t.Errorf("mediaType(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestMediaTypeTable holds every entry to the shape a content-type field value has, so
// that a new line in the table cannot be a malformed field value.
//
// §8.3.1 of RFC 9110 gives the grammar: a type, a slash, a subtype, and parameters after
// semicolons. Nothing here needs a general parser — what a mistyped entry looks like is a
// missing slash, a stray space, or a charset on something that has no characters — but a
// field value assembled by hand and never checked is a field value nobody has read since
// it was written.
func TestMediaTypeTable(t *testing.T) {
	if len(mediaTypes) == 0 {
		t.Fatal("the media type table is empty")
	}

	for ext, value := range mediaTypes {
		switch {
		case !strings.HasPrefix(ext, "."):
			t.Errorf("the key %q does not begin with a dot, so path.Ext can never return it", ext)
		case ext != strings.ToLower(ext):
			t.Errorf("the key %q is not lower-cased, so the folded lookup can never find it", ext)
		case len(ext) < 2:
			t.Errorf("the key %q is a dot and nothing else", ext)
		}

		kind, params, _ := strings.Cut(value, ";")
		if strings.Count(kind, "/") != 1 || strings.HasPrefix(kind, "/") || strings.HasSuffix(kind, "/") {
			t.Errorf("%q maps to %q, which is not a type and a subtype", ext, value)
		}
		if strings.TrimSpace(kind) != kind {
			t.Errorf("%q maps to %q, whose type is padded with space", ext, value)
		}
		if kind != strings.ToLower(kind) {
			t.Errorf("%q maps to %q, which is not lower-cased", ext, value)
		}

		// A charset for the text types and for nothing else, which is the rule stated
		// in this file's own comment. Both directions are checked: a text type without
		// one is a browser guessing an encoding, and a charset on a font is a parameter
		// the format has no use for.
		wantCharset := strings.HasPrefix(kind, "text/")
		if got := params != ""; got != wantCharset {
			t.Errorf("%q maps to %q; a charset parameter %s be there",
				ext, value, map[bool]string{true: "should", false: "should not"}[wantCharset])
		}
		if params != "" && params != " charset=utf-8" {
			t.Errorf("%q maps to %q; the only parameter this table states is a UTF-8 charset",
				ext, value)
		}
	}
}

// TestMediaTypeDefaultIsNotInTheTable keeps the default a default.
//
// An extension mapped explicitly to application/octet-stream would be indistinguishable
// from one this table has never heard of, which makes it a line that cannot be tested and
// that the next reader has to think about.
func TestMediaTypeDefaultIsNotInTheTable(t *testing.T) {
	for ext, value := range mediaTypes {
		if value == octetStream {
			t.Errorf("%q maps to %q explicitly, which is what an absent key already means",
				ext, value)
		}
	}
}

// TestMediaTypeHTMLIsDeliberate is the entry whose being wrong is a security bug.
//
// Exactly the extensions a browser navigates to may be served as HTML. Anything else
// mapped to text/html would be a file whose content runs as script in this origin — an
// upload directory served with .txt as HTML is the whole shape of a stored-XSS bug — and
// an .html that is not HTML is a page offered as a download.
func TestMediaTypeHTMLIsDeliberate(t *testing.T) {
	html := map[string]bool{".html": true, ".htm": true}

	for ext, value := range mediaTypes {
		kind, _, _ := strings.Cut(value, ";")
		if kind == "text/html" && !html[ext] {
			t.Errorf("%q maps to %q, so a file with that extension runs as script here", ext, value)
		}
	}
	for ext := range html {
		if kind, _, _ := strings.Cut(mediaTypes[ext], ";"); kind != "text/html" {
			t.Errorf("%q maps to %q, want text/html", ext, mediaTypes[ext])
		}
	}
}
