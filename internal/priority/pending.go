package priority

// Pending is the buffered priorities of streams that have been prioritized and not opened.
//
// A client MAY send a PRIORITY_UPDATE frame before the stream it names exists, and it is
// the useful case rather than the odd one: it lets a client state a response's priority
// without spending a header field on it, and it is the only way to prioritize a stream
// whose request is still queued behind other requests. §7 of RFC 9218: "Servers SHOULD
// buffer the most recently received PRIORITY_UPDATE frame and apply it once the referenced
// stream is opened."
//
// Discarding those frames instead would lose the priority of exactly the requests a client
// cared enough to prioritize, silently, on every connection that pipelines its signals
// ahead of its requests — which is what a browser does.
//
// # What bounds it
//
// A map keyed by whatever a peer sends is a memory-exhaustion attack unless something
// bounds it. §7 of RFC 9218 says as much and leaves the bound open: "Holding
// PRIORITY_UPDATE frames for each stream requires server resources, which can be bounded
// by local implementation policy." Three things bound this one, and none is a number
// invented here.
//
// Per stream, Put overwrites. §7 of RFC 9218: "Although there is no limit to the number of
// PRIORITY_UPDATE frames that can be sent, storing only the most recently received frame
// limits resource commitment." Ten thousand frames for one stream occupy one entry, and
// the tenth thousandth is the one that counts, which is also what the specification wants
// applied.
//
// Across streams, the bound is normative rather than local: §7.1 of RFC 9218 caps the
// streams that have been prioritized but remain idle plus the active streams at
// SETTINGS_MAX_CONCURRENT_STREAMS, and makes a PRIORITY_UPDATE that would exceed it a
// connection error. So the size of this is bounded by a limit this server chose and
// advertised. Held and Len are here because the caller enforces that rule — it is the half
// that needs the count of active streams — and it cannot enforce it without asking whether
// an entry already exists, since replacing one does not make the count rise.
//
// And Prune is what keeps the cap from being the only thing standing between a peer and
// the memory: a client that escapes the concurrency limit by skipping stream identifiers
// closes every stream it skipped in the act of doing so.
//
// # Not safe for concurrent use
//
// One connection's read loop owns one of these, and nothing else touches it. That is the
// same ownership internal/server's other per-connection state has, and it is why there is
// no mutex here: a lock would suggest a second goroutine exists.
type Pending struct {
	// of is keyed by prioritized stream identifier, and is created on first use so that a
	// connection which never receives a PRIORITY_UPDATE allocates nothing for one.
	//
	// A Go map does not return its buckets, so this grows to the high-water mark of
	// concurrent pending streams and stays there for the life of the connection. That is
	// bounded, and bounded by a small number, which is the argument for a map here rather
	// than something that shrinks.
	of map[uint32]Params
}

// Put records params as the priority of stream id, replacing any priority already buffered
// for it. The most recent frame is the one that survives, which is both what §7 of RFC 9218
// asks for and what bounds the entry to one per stream.
//
// The caller is responsible for the rule in §7.1 of RFC 9218 that bounds how many streams
// may be pending at once; see Held and Len. This does not enforce it, because the
// consequence of breaking it is a connection error, and a data structure that returned an
// error some callers would have to translate into one is a worse arrangement than a caller
// that asks first.
func (p *Pending) Put(id uint32, params Params) {
	if p.of == nil {
		p.of = make(map[uint32]Params)
	}
	p.of[id] = params
}

// Take returns the priority buffered for stream id and forgets it, reporting whether there
// was one. It is called when the stream opens, which is the moment §7 of RFC 9218 says to
// apply the buffered frame, and the entry is dropped in the same step because a stream that
// exists holds its own priority from then on.
func (p *Pending) Take(id uint32) (Params, bool) {
	params, ok := p.of[id]
	if ok {
		delete(p.of, id)
	}
	return params, ok
}

// Held reports whether a priority is buffered for stream id.
//
// It exists for the caller's §7.1 of RFC 9218 check and not for reading a priority: a
// caller that asks this and then calls Put is deciding whether the number of prioritized
// idle streams is about to rise, which is the quantity that rule is about.
func (p *Pending) Held(id uint32) bool {
	_, ok := p.of[id]
	return ok
}

// Len is how many streams have a priority buffered. With the count of active streams it is
// the left-hand side of §7.1 of RFC 9218's limit.
func (p *Pending) Len() int { return len(p.of) }

// Prune forgets the buffered priorities of streams that can no longer be opened, and
// returns how many it forgot. below is the identifier of a stream that has just left the
// idle state; entries at that identifier are left alone, because Take is what consumes
// that one and may be called either side of this.
//
// §5.1.1 of RFC 9113: "When a stream transitions out of the 'idle' state, all streams in
// the 'idle' state that might have been opened by the peer with a lower-valued stream
// identifier immediately transition to 'closed'." So the moment a client opens stream 101,
// every lower-numbered stream it had prioritized and not opened is closed rather than idle,
// and the priority buffered for it is a priority for a stream that will never exist. Both
// halves of that matter: the entry is dead weight, and it must stop counting towards §7.1
// of RFC 9218's limit, which is written about idle streams and would otherwise be reduced
// by streams that are not.
//
// This is what makes the bound in the type comment hold without a timer or a cap of its
// own. A client that prioritizes a thousand streams and opens none of them is refused by
// the concurrency limit; a client that skips ahead to a high identifier to escape that
// limit closes every entry below it in the act of skipping. There is no order of frames
// that keeps an entry alive without either opening its stream or staying inside the limit
// this server advertised.
//
// Every entry here is a stream the peer could open, which is what makes the comparison the
// whole of the test rather than a comparison plus a parity check: §7.1 of RFC 9218 makes a
// PRIORITY_UPDATE naming a server-initiated stream a connection error, so the caller never
// buffers one.
func (p *Pending) Prune(below uint32) int {
	n := 0
	for id := range p.of {
		if id < below {
			delete(p.of, id)
			n++
		}
	}
	return n
}
