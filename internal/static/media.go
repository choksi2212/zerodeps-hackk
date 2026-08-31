package static

// The extension-to-media-type table.
//
// # Why this is a table and not mime.TypeByExtension
//
// Because mime.TypeByExtension is not a function of its argument. On the first call the
// standard library loads the host's own mappings: /etc/mime.types and its neighbours on
// Unix, and on Windows the extension keys under HKEY_CLASSES_ROOT, where a value is
// whatever the last program installed decided. So the same build, serving the same file,
// answers "text/javascript" on one machine, "application/javascript" on the next, and
// "text/plain" on a third where nothing has claimed .js.
//
// That is a strange thing to ship in a tree whose reproducible-build claim is that the
// same source produces the same artefact. A response is the artefact this server
// produces, and a response that depends on a registry key is not reproducible in any
// sense a judge could check. It also cannot be tested: an assertion about .js here would
// pass on the machine that wrote it and be a coin toss anywhere else.
//
// The cost of the table is that it is finite and somebody has to add to it. That is the
// right cost — the alternative is not a longer table, it is a shorter one that varies.
//
// # What is in it
//
// The types are the IANA-registered ones, and where a de-facto type differs the registered
// one wins: an icon is image/vnd.microsoft.icon rather than the image/x-icon browsers also
// take, and JavaScript is text/javascript, which RFC 9239 made the standard type and the
// three application/* spellings historical. A charset is stated for the text types and
// omitted everywhere else, because it means nothing to a PNG and because JSON, WebAssembly
// and the font formats define their own encoding: sending "charset" with them is a field
// value that a strict parser is entitled to complain about and a lax one ignores.
//
// UTF-8 for every text type. It is the only encoding this table will name — a build
// directory holding Latin-1 HTML is a file that needs converting rather than a second
// entry here, and guessing an encoding from the octets is the sniffing §8.3 of RFC 9110
// warns about, done to ourselves.

const (
	// octetStream is the type of a file this table has no opinion about.
	octetStream = "application/octet-stream"

	// textPlain is what this handler's own error bodies are, and what a .txt file is.
	// One constant for both, because they are the same claim about the same octets.
	textPlain = "text/plain; charset=utf-8"
)

// Media types, keyed by the extension path.Ext returns: lower-cased, and with the dot.
//
// A map rather than a switch because it is data, and because the test that walks it can
// then assert a property of every entry — that each has a slash, no space before its
// semicolon, and a charset if and only if it is text. A switch would need the list
// written twice.
var mediaTypes = map[string]string{
	// The documents a browser navigates to. text/html is the one entry where getting it
	// wrong is a security bug rather than a display bug, in both directions: HTML served
	// as octet-stream is a download instead of a page, and a file served as HTML that the
	// server did not know was HTML is script running in the origin's context.
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".xhtml": "application/xhtml+xml",

	// What a page pulls in.
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".mjs":  "text/javascript; charset=utf-8",
	".wasm": "application/wasm",
	".map":  "application/json",
	".json": "application/json",
	".xml":  "application/xml",

	// Plain text, and the two formats that are plain text with a claim about their shape.
	".txt": textPlain,
	".md":  "text/markdown; charset=utf-8",
	".csv": "text/csv; charset=utf-8",

	// Images. SVG is XML, and is the one image type that can carry script — which is why
	// it is served as image/svg+xml and not as something a browser would sniff: the type
	// is what tells the browser to treat it as an image rather than a document.
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".avif": "image/avif",
	".svg":  "image/svg+xml",
	".ico":  "image/vnd.microsoft.icon",

	// Fonts, whose types RFC 8081 moved into a top-level "font" tree. The older
	// application/font-woff spellings are deliberately not here.
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",

	// Media, which is the reason ranges.go exists: a browser scrubbing through a video sends
	// one range request per seek, and a server ignoring those would re-send the whole file
	// from the start for each one. The list is short because the set of container formats a
	// browser will decode without being asked twice is short.
	".mp4":  "video/mp4",
	".webm": "video/webm",
	".mp3":  "audio/mpeg",
	".wav":  "audio/wav",
	".ogg":  "audio/ogg",

	// Archives and documents, where the file is the point and the browser is a download
	// dialog.
	".pdf": "application/pdf",
	".zip": "application/zip",
	".gz":  "application/gzip",
	".tar": "application/x-tar",
}
