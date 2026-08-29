// Package hpack implements RFC 7541 (HPACK: Header Compression for HTTP/2):
// the 61-entry static table, the per-connection dynamic table, and the full
// set of header-field representations. It is a pure codec — bytes in,
// []h2.Field out; []h2.Field in, bytes out — with no knowledge of HTTP
// semantics, frames, streams, or sockets.
package hpack

import "zerodeps/zdh/internal/h2"

// Codec is an HPACK codec for one direction of one connection. It satisfies
// h2.HeaderCodec.
//
// Codec is not safe for concurrent use, and that is deliberate: the dynamic
// table is connection-scoped and order-dependent. Every header block on a
// connection must be decoded in the exact order it arrived, from a single
// goroutine; encoding likewise from a single goroutine (or under a mutex
// the writer owns). A mutex alone would not fix a caller that decodes out
// of order — mutual exclusion is not the same guarantee as ordering — so
// none is added here. See docs/HPACK.md.
type Codec struct {
	dyn *dynamicTable
}

// New returns a Codec with an empty dynamic table at the default size
// (RFC 9113 §6.5.2, 4096 octets).
func New() *Codec {
	return &Codec{dyn: newDynamicTable()}
}

// SetMaxDynamicTableSize applies a peer SETTINGS_HEADER_TABLE_SIZE value
// (RFC 7541 §4.2), evicting entries as needed to fit. It is also the
// ceiling that an in-band Dynamic Table Size Update (§6.3) encountered
// during Decode may not exceed.
func (c *Codec) SetMaxDynamicTableSize(n int) {
	c.dyn.setCeiling(n)
}

var _ h2.HeaderCodec = (*Codec)(nil)
