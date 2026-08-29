package limits

// The frame-layer bounds. These are policy: the numbers this server chooses. The
// frame reader enforces them, because it is the layer holding the running totals,
// and it carries its own identical defaults so that the package stands alone in a
// test. TestFrameBoundsMatchTheFrameLayer asserts the two agree, so changing one
// without the other fails the build rather than leaving a server whose configured
// bound and its fallback disagree.
const (
	// MaxFrameSize is the SETTINGS_MAX_FRAME_SIZE this server advertises, and so
	// the largest payload a peer may send. It is deliberately left at the
	// protocol's initial value (§6.5.2) rather than raised.
	//
	// The frame size is the size of the buffer a peer can make us allocate and
	// hold for the lifetime of a connection. At 16 KiB, ten thousand connections
	// cost 160 MiB of read buffer; at the protocol maximum of 2^24-1 the same
	// connections cost 160 GiB, and a single peer can demand 16 MiB by sending
	// one frame header. Raising it would buy a marginal throughput gain on
	// large bodies in exchange for making memory a function of peer behaviour.
	MaxFrameSize = 1 << 14

	// MaxHeaderBlockSize bounds the total octets of a single header block —
	// a HEADERS or PUSH_PROMISE frame plus every CONTINUATION that follows it.
	//
	// This is one of the two bounds that answer CVE-2023-45288. A header block
	// has no length field of its own: it ends when a frame arrives with
	// END_HEADERS, and until then a receiver must buffer everything, because
	// HPACK cannot be decoded from the middle. Without a bound, "until then" is
	// as long as the peer likes.
	//
	// 128 KiB is roughly sixty times the header block a browser actually sends,
	// which is the right side to err on: a request refused for being too large
	// is a bug report, and the memory saved by a tighter bound is not the
	// resource under attack here.
	MaxHeaderBlockSize = 1 << 17

	// MaxContinuationFrames bounds the number of CONTINUATION frames in one
	// header block, and it is the other half of the CVE-2023-45288 answer.
	//
	// The two bounds are not redundant, and neither alone is sufficient. Eight
	// full-size CONTINUATION frames reach MaxHeaderBlockSize; the size bound
	// catches that. Ten thousand CONTINUATION frames carrying one octet each
	// total ten kilobytes, so the size bound never fires — but each frame costs
	// a header parse and a bounds check, and that is the attack as it was
	// actually reported. Only a count bound catches it.
	//
	// 32 is far more than any real client needs: a browser sends its request
	// headers in one frame. A client whose headers genuinely need more than
	// half a megabyte of frames is not a client this server is for.
	MaxContinuationFrames = 32
)

// MaxConcurrentStreams is the SETTINGS_MAX_CONCURRENT_STREAMS this server
// advertises (§5.1.2). It bounds the number of streams a single connection can
// have open at once, and therefore the number of goroutines and request buffers
// one peer can hold.
//
// 100 is what browsers expect: it is the value Chrome, Firefox and Go's own
// HTTP/2 client are tuned against, and a lower value shows up as stalled requests
// on a page with many resources. It is not a defence against the reset attack —
// the whole point of CVE-2023-44487 is that a stream reset immediately never
// counts against this limit at all — which is why ResetBurst exists separately.
//
// Enforced in internal/stream, which owns the stream table.
const MaxConcurrentStreams = 100

// MaxEncoderTableSize bounds the HPACK dynamic table this server keeps for the
// direction it sends in, whatever the peer's SETTINGS_HEADER_TABLE_SIZE asks for.
//
// That setting is the one parameter in §6.5.2 with no upper bound of its own. A peer
// may advertise 2^32-1 and be entirely within the protocol, having asked this server
// for four gigabytes of encoding context on one connection in a six-octet SETTINGS
// entry, before it has sent a request. Multiplied by MaxConns it is not a number
// worth naming.
//
// Sitting below what the peer offered is legal and costs nothing. §4.2 of RFC 7541
// makes the value "the maximum size the encoder is permitted to use" rather than the
// size it must use, and lets an encoder choose any size below it provided it says
// which — with a dynamic table size update at the front of the next block, which is
// the encoder's own business. So a peer that offers a larger table than this gets the
// responses it would have got anyway, encoded against a smaller one.
//
// Which way the bound applies is the part worth being careful about: it lowers the
// value the peer sent and never raises it. A peer that advertises a table smaller
// than HPACK's default, or none at all, is the party that has to decode our indices,
// so that direction is obeyed rather than chosen — an encoder referring to entries
// the decoder is not keeping produces field lines nobody sent. A minimum, then, and
// not a clamp into a range.
//
// 64 KiB is sixteen times HPACK's 4096-octet default, which is what browsers
// actually advertise, and 32 MiB across MaxConns. Beyond it the compression a larger
// table buys is nothing: a dynamic table holds the field lines a *later* response
// repeats, and this server's responses repeat about a dozen.
//
// Enforced in internal/stream, where the setting arrives from internal/server and
// meets the encoder. Bounding it there also removes a narrowing that would otherwise
// need a guard no test could reach: the setting arrives as a uint32 and the codec
// takes an int, so a peer's 2^32-1 would be -1 on a 32-bit platform.
const MaxEncoderTableSize = 1 << 16

// MaxConns is how many connections this server serves at once.
//
// It is the outermost bound, and the one the others are multiplied by: every
// per-connection cost in this file — a 16 KiB read buffer, a 4 KiB write buffer,
// two goroutines, transiently up to MaxHeaderBlockSize while a header block is
// being assembled, and up to MaxEncoderTableSize for as long as a peer asks for it
// — is paid once per connection here. 512 connections is about 10 MiB of steady
// buffers and, in the worst case a peer can arrange, 64 MiB of header blocks and
// 32 MiB of encoder tables.
//
// The number is chosen against file descriptors rather than memory, because that
// is the limit reached first. A process on Linux typically starts with a soft limit
// of 1024 descriptors, shared with the listener, the certificate, the log and
// whatever the runtime holds; a server that accepted a thousand connections would
// spend its last descriptors and then fail to accept anything, which is an outage
// arriving as a load spike. Half the commonest limit leaves that headroom.
//
// The bound is enforced by not accepting rather than by accepting and closing.
// A refused connection sits in the kernel's backlog, where it is either served a
// moment later or times out at the client as a connection that was never
// established — which is the truth. Accept-then-close spends the descriptor, the
// TLS handshake and the peer's trust in a connection it was told it had.
const MaxConns = 512

// The rapid-reset bounds, which answer CVE-2023-44487.
//
// The attack is a client that opens a stream and resets it immediately, over and
// over. Every frame is valid, no rule is broken, and the concurrent-stream limit
// never engages because no stream stays open — but the server has still done the
// work of decoding the headers and dispatching a request for each one. A single
// connection can drive many times the request rate its stream limit implies.
//
// The only thing that distinguishes this from a fast, legitimate client is the
// rate of resets over time, which is why this is a token bucket rather than a
// count. See Bucket.
const (
	// ResetBurst is how many stream resets a connection may make before the rate
	// matters. It is generous on purpose: a user navigating away from a page
	// legitimately cancels every request in flight at once, and a browser with a
	// hundred requests open will send a hundred RST_STREAMs in a burst that
	// should not be mistaken for an attack.
	ResetBurst = 100

	// ResetRefillPerSecond is the sustained reset rate a connection may hold once
	// the burst is spent. Twenty a second is far above any browsing pattern and
	// far below the rate that makes the attack worth mounting.
	ResetRefillPerSecond = 20
)
