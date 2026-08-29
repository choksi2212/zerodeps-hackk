package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"

	"zerodeps/zdh/internal/limits"
)

// The defaults are the whole of what `zdh` with no arguments does, so they are
// asserted as values rather than trusted to the flag declarations that set them:
// a default silently changed is a demonstration that serves the wrong directory
// or listens on the wrong port, and nothing else in the suite would notice.
func TestParseDefaults(t *testing.T) {
	var errOut bytes.Buffer
	o, err := parse(nil, &errOut)
	if err != nil {
		t.Fatalf("parse(nil) = %v, want no error", err)
	}
	if errOut.Len() != 0 {
		t.Errorf("parse wrote to stderr with no arguments to complain about: %q", errOut.String())
	}

	want := options{
		dir:      ".",
		tlsAddr:  ":8443",
		h2cAddr:  ":8081",
		certPath: "zdh-cert.pem",
		keyPath:  "zdh-key.pem",
		maxConns: limits.MaxConns,
	}
	if *o != want {
		t.Errorf("parse(nil) = %+v, want %+v", *o, want)
	}
}

func TestParseFlags(t *testing.T) {
	var errOut bytes.Buffer
	o, err := parse([]string{
		"-dir", "public",
		"-addr", "127.0.0.1:9443",
		"-h2c", "",
		"-cert", "c.pem",
		"-key", "k.pem",
		"-host", "example.test",
		"-max-conns", "7",
	}, &errOut)
	if err != nil {
		t.Fatalf("parse = %v, want no error", err)
	}

	want := options{
		dir:      "public",
		tlsAddr:  "127.0.0.1:9443",
		h2cAddr:  "",
		certPath: "c.pem",
		keyPath:  "k.pem",
		hosts:    "example.test",
		maxConns: 7,
	}
	if *o != want {
		t.Errorf("parse = %+v, want %+v", *o, want)
	}
}

// A bare word on the command line is somebody expecting a subcommand. It must be
// refused rather than ignored, and the refusal must name the word: "unexpected
// argument" without the argument is a message a user cannot act on.
func TestParseRejectsPositionalArgument(t *testing.T) {
	var errOut bytes.Buffer
	if _, err := parse([]string{"serve", "-dir", "public"}, &errOut); !errors.Is(err, errUsage) {
		t.Fatalf("parse = %v, want errUsage", err)
	}

	got := errOut.String()
	if !strings.Contains(got, `unexpected argument "serve"`) {
		t.Errorf("stderr does not name the argument:\n%s", got)
	}
	// The usage follows the complaint, so somebody who typed a subcommand learns
	// what this program actually takes without running it again.
	if !strings.Contains(got, "usage: zdh") || !strings.Contains(got, "-dir") {
		t.Errorf("stderr does not carry the usage:\n%s", got)
	}
}

func TestParseRejectsUnknownFlag(t *testing.T) {
	var errOut bytes.Buffer
	if _, err := parse([]string{"-nonesuch"}, &errOut); !errors.Is(err, errUsage) {
		t.Fatalf("parse = %v, want errUsage", err)
	}
	if !strings.Contains(errOut.String(), "nonesuch") {
		t.Errorf("stderr does not name the flag:\n%s", errOut.String())
	}
}

// Diagnostics belong on stderr even when the parse succeeds in the end, because
// a shell redirecting stdout to a file is collecting the server's startup lines
// and not its complaints.
func TestParseWritesNothingToStdout(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-nonesuch"}, &out, &errOut); !errors.Is(err, errUsage) {
		t.Fatalf("run = %v, want errUsage", err)
	}
	if out.Len() != 0 {
		t.Errorf("a rejected command line wrote to stdout: %q", out.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-version"}, &out, &errOut); err != nil {
		t.Fatalf("run(-version) = %v, want no error", err)
	}
	if !strings.Contains(out.String(), "dependencies: 0\n") {
		t.Errorf("-version did not print the dependency count:\n%s", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("-version wrote to stderr: %q", errOut.String())
	}
}

// Disabling both listeners is a command line that asks for a server with no way
// in. It is a usage mistake and exits like one — the alternative, a process that
// starts and then does nothing forever, is the worst of the three possible
// behaviours.
func TestRunRejectsNoListeners(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"-addr", "", "-h2c", ""}, &out, &errOut)
	if !errors.Is(err, errUsage) {
		t.Fatalf("run = %v, want errUsage", err)
	}
	got := errOut.String()
	for _, want := range []string{"-addr", "-h2c"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr does not name %s:\n%s", want, got)
		}
	}
	if out.Len() != 0 {
		t.Errorf("wrote to stdout: %q", out.String())
	}
}

func TestCertHosts(t *testing.T) {
	// The three names a local demonstration is reached at, in the order the
	// certificate carries them.
	const local = "localhost,127.0.0.1,::1"

	for _, tc := range []struct {
		name  string
		addr  string
		extra string
		want  string
	}{
		{"the default wildcard address adds nothing", ":8443", "", local},
		{"an every-interface address adds nothing", "0.0.0.0:8443", "", local},
		{"an IPv6 wildcard adds nothing", "[::]:8443", "", local},
		{"an address already covered is not repeated", "127.0.0.1:8443", "", local},
		{"a named address is added", "example.test:8443", "", local + ",example.test"},
		{"-host is added", ":8443", "demo.test", local + ",demo.test"},
		{"-host takes a list, and is trimmed", ":8443", "a.test, b.test ", local + ",a.test,b.test"},
		{"-host repeating a default is not repeated", ":8443", "localhost", local},
		{"an empty -host entry is dropped", ":8443", "a.test,,", local + ",a.test"},

		// An address the net package cannot split is not this function's to
		// diagnose: the listener will fail on it in a moment and say so with the
		// address in hand. Contributing a garbage SAN in the meantime would turn
		// one clear error into a certificate nobody can explain.
		{"an unsplittable address is ignored", "not-an-address", "", local},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(certHosts(tc.addr, tc.extra), ",")
			if got != tc.want {
				t.Errorf("certHosts(%q, %q) = %q, want %q", tc.addr, tc.extra, got, tc.want)
			}
		})
	}
}

// stringAddr is a net.Addr that is only its own text, which is all browserHost
// reads. Binding real sockets to test a string function would make the test
// depend on which addresses this machine happens to have.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func TestBrowserHost(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		// A wildcard is not somewhere a browser can go, and localhost is where
		// the demonstration is actually reached.
		{"0.0.0.0:8443", "localhost:8443"},
		{"[::]:8443", "localhost:8443"},
		{":8443", "localhost:8443"},

		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"192.168.1.9:8443", "192.168.1.9:8443"},

		// The brackets are the authority's, not the address's, so they have to
		// survive the round trip through SplitHostPort.
		{"[::1]:8443", "[::1]:8443"},

		// Nothing to split. Printing it unchanged is better than printing a
		// truncated version of it.
		{"a-name-with-no-port", "a-name-with-no-port"},
	} {
		if got := browserHost(stringAddr(tc.addr)); got != tc.want {
			t.Errorf("browserHost(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestBindOpensBothListeners(t *testing.T) {
	// A real configuration rather than nil, because which listener carries it is
	// the difference between h2 and h2c and a nil here cannot tell them apart:
	// a cleartext binding that wrongly held a TLS configuration would look
	// identical to a correct one.
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	bs, err := bind(&options{tlsAddr: "127.0.0.1:0", h2cAddr: "127.0.0.1:0"}, tlsCfg)
	if err != nil {
		t.Fatalf("bind = %v, want no error", err)
	}
	t.Cleanup(func() {
		for _, b := range bs {
			b.l.Close()
		}
	})

	if len(bs) != 2 {
		t.Fatalf("bind opened %d listeners, want 2", len(bs))
	}
	if !strings.HasPrefix(bs[0].url, "https://127.0.0.1:") {
		t.Errorf("the TLS binding's URL is %q, want an https URL", bs[0].url)
	}
	if !strings.Contains(bs[0].note, `ALPN "h2"`) {
		t.Errorf("the TLS binding's note does not mention ALPN: %q", bs[0].note)
	}
	// The https URL is a promise, and the configuration is what keeps it. Without
	// this the accept loop would serve the preface in the clear on a port whose
	// startup line told a browser to handshake.
	if bs[0].tlsCfg != tlsCfg {
		t.Error("the TLS binding does not carry the TLS configuration")
	}
	if !strings.HasPrefix(bs[1].url, "http://127.0.0.1:") {
		t.Errorf("the h2c binding's URL is %q, want an http URL", bs[1].url)
	}
	// A cleartext listener has no TLS configuration, and that nil is what tells
	// the accept loop to serve h2c by prior knowledge instead of handshaking.
	if bs[1].tlsCfg != nil {
		t.Error("the h2c binding carries a TLS configuration")
	}
	// Both URLs must be reachable, which is the part a startup line printing a
	// wildcard would get wrong.
	if bs[0].url == bs[1].url {
		t.Errorf("both bindings print the same URL: %q", bs[0].url)
	}
}

func TestBindNothingRequested(t *testing.T) {
	bs, err := bind(&options{}, nil)
	if err != nil {
		t.Fatalf("bind = %v, want no error", err)
	}
	if len(bs) != 0 {
		t.Errorf("bind opened %d listeners for a request for none", len(bs))
	}
}

// The failure that matters: a server asked for two ports where the second is
// taken must leave neither open. Otherwise the port it did get stays held by a
// process that is about to exit, and the next run fails on the *first* port for
// a reason that has nothing to do with the mistake.
func TestBindClosesWhatItOpenedOnFailure(t *testing.T) {
	// A socket to collide with, kept open for the length of the test.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("opening the socket to collide with: %v", err)
	}
	defer taken.Close()

	// An address that is free right now, so the first bind succeeds and there is
	// something to clean up when the second one fails. Closed immediately: a
	// listening socket that never accepted a connection does not linger, so this
	// port is available again at once.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	addr := free.Addr().String()
	free.Close()

	bs, err := bind(&options{tlsAddr: addr, h2cAddr: taken.Addr().String()}, nil)
	if err == nil {
		for _, b := range bs {
			b.l.Close()
		}
		t.Fatal("bind succeeded on an address already in use")
	}
	if bs != nil {
		t.Errorf("bind returned %d bindings alongside an error", len(bs))
	}

	// The assertion: the first port is free again. If bind had leaked it, this is
	// the call that fails — which is exactly the failure the next run of the
	// server would have hit.
	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the first listener was not closed after the second failed: %v", err)
	}
	again.Close()
}
