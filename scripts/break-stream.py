"""Deliberately break internal/stream/stream.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

stream.go is a small file with two things in it that are worth breaking and a lot of
prose that is not. The two are recvEnd, which is the only arithmetic in the package
that §5.1 spells out twice, and State.String, which is a five-way switch nobody
would think to test.

  recvEnd's whole reason for existing is that "the peer has finished sending" is a
  different transition depending on what this server has already sent: from open it
  is half-closed (remote), and from half-closed (local) -- where our own END_STREAM
  has gone -- it is closed. Get it wrong in the direction the breaks below take and
  a stream this server had finished with is resurrected as one it still owes a
  response, which is a stream that never leaves the table and a request that never
  gets an answer. The two orders of closing are separately tested for exactly this
  reason.

  State.String looks like decoration. It is not: these strings are interpolated into
  the STREAM_CLOSED and PROTOCOL_ERROR messages this server sends, so they are read
  next to h2spec output by someone who has §5.1's figure open. Naming the wrong
  direction -- half-closed (local) for a stream the *peer* has finished with -- sends
  a bug report in the opposite direction from the bug, and every one of those breaks
  leaves a server that works.

peerDone is one comparison against one state, and the comment above it claims that
is exact because a Stream only ever exists in three states. Both breaks on it are
there to check that the claim is load-bearing rather than decorative: widening the
comparison to "anything but open" refuses a frame §5.1 permits, and narrowing it to
false accepts two frames §5.1 forbids.

The three accessors are one line each and are broken because a one-line body is where
a reader stops looking. Two of them used to be four: there was a SendWindow beside
RecvWindow, and the pair were broken against each other, because `return s.recv` where
`return s.send` was meant was the single most plausible typo in the file -- both are
*flow.Window, both have the same methods, and one of them was the peer's to spend. The
send window has since moved behind internal/flow's Sender, which is what makes that
typo unwritable rather than merely unwritten, and the break that used to catch it is
gone with it. What is left is RecvWindow answering with a window that is not the
stream's, which is the same class of mistake and the only one still expressible.

One hole on the first run, and it was in this file rather than in the code or the
tests. The break that stops recvEnd from closing a stream this server has already
finished sending on named TestAnEmptyDataFrameWithEndStreamClosesAnExhaustedStream
among the tests that must fail. It cannot: that test never calls SendEnd, so its
stream is never in half-closed (local), which is the only state the break changes.
Three other tests caught it and the name has been withdrawn. A name in this list is a
claim about a particular test, and the harness holds it to the claim rather than
accepting that the break was caught by something.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/stream/stream.go"
PKG = "./internal/stream/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- State.String: what an error message says --------------------------
    (
        "String has no name for an idle stream, so a protocol error reports it as unknown",
        """	case StateIdle:
		return "idle"
""",
        "",
        ["TestStateStringsNameTheRfcsOwnStates"],
    ),
    (
        "String names the idle state something 5.1's figure does not",
        """	case StateIdle:
		return "idle\"""",
        """	case StateIdle:
		return "unused\"""",
        ["TestStateStringsNameTheRfcsOwnStates"],
    ),
    (
        "String names the open state something 5.1's figure does not",
        """	case StateOpen:
		return "open\"""",
        """	case StateOpen:
		return "active\"""",
        [
            "TestStateStringsNameTheRfcsOwnStates",
            "TestHeadersOpensAStreamAndDeliversItsFields",
        ],
    ),
    (
        "String reports a stream the peer has finished with as one this server has",
        """	case StateHalfClosedRemote:
		return "half-closed (remote)\"""",
        """	case StateHalfClosedRemote:
		return "half-closed (local)\"""",
        [
            "TestStateStringsNameTheRfcsOwnStates",
            "TestTrailersEndTheStreamAndCarryTheirOwnFields",
        ],
    ),
    (
        "String reports a stream this server has finished with as one the peer has",
        """	case StateHalfClosedLocal:
		return "half-closed (local)\"""",
        """	case StateHalfClosedLocal:
		return "half-closed (remote)\"""",
        ["TestStateStringsNameTheRfcsOwnStates"],
    ),
    (
        "String has no name for a closed stream",
        """	case StateClosed:
		return "closed"
""",
        "",
        ["TestStateStringsNameTheRfcsOwnStates"],
    ),
    (
        "String reports a state that does not exist as a closed stream",
        """	return "unknown\"""",
        """	return "closed\"""",
        ["TestStateStringsNameTheRfcsOwnStates"],
    ),

    # --- recvEnd: the transition 5.1 spells out twice -----------------------
    (
        "recvEnd resurrects a stream this server had already finished sending on",
        """	if s.state == StateHalfClosedLocal {""",
        """	if false {""",
        [
            "TestStateOfTracksTheOtherOrderOfClosing",
            "TestDataWithEndStreamClosesAStreamWeHadFinished",
            "TestTrailersCloseAStreamWeHadAlreadyFinished",
        ],
    ),
    (
        "recvEnd leaves a stream both ends have finished with half closed",
        """		s.state = StateClosed
		return""",
        """		return""",
        [
            "TestStateOfTracksTheOtherOrderOfClosing",
            "TestDataWithEndStreamClosesAStreamWeHadFinished",
            "TestTrailersCloseAStreamWeHadAlreadyFinished",
        ],
    ),
    (
        "recvEnd closes a stream this server has not answered yet",
        """	s.state = StateHalfClosedRemote""",
        """	s.state = StateClosed""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestHeadersWithEndStreamLeavesTheStreamHalfClosed",
            "TestDataOnAHalfClosedStreamIsAStreamError",
        ],
    ),
    (
        "recvEnd has the two states of 5.1's transition the wrong way round",
        """	if s.state == StateHalfClosedLocal {""",
        """	if s.state == StateOpen {""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestHeadersWithEndStreamLeavesTheStreamHalfClosed",
        ],
    ),

    # --- peerDone: whether the comparison against one state is exact --------
    (
        "peerDone never reports the peer as finished, so 5.1's STREAM_CLOSED is unreachable",
        """func (s *Stream) peerDone() bool { return s.state == StateHalfClosedRemote }""",
        """func (s *Stream) peerDone() bool { return false }""",
        [
            "TestDataOnAHalfClosedStreamIsAStreamError",
            "TestTrailersOnAHalfClosedStreamAreAStreamError",
        ],
    ),
    (
        "peerDone reports a stream this server finished with as one the peer did",
        """func (s *Stream) peerDone() bool { return s.state == StateHalfClosedRemote }""",
        """func (s *Stream) peerDone() bool { return s.state != StateOpen }""",
        ["TestDataOnAStreamWeHaveFinishedIsStillAccepted"],
    ),

    # --- the accessors: two windows that look identical at the call site ----
    (
        "ID is not the identifier the peer opened, so every response is written to the wrong stream",
        """func (s *Stream) ID() uint32 { return s.id }""",
        """func (s *Stream) ID() uint32 { return s.id + 2 }""",
        ["TestHeadersOpensAStreamAndDeliversItsFields"],
    ),
    (
        "State is open for every stream, including one the peer has finished with",
        """func (s *Stream) State() State { return s.state }""",
        """func (s *Stream) State() State { return StateOpen }""",
        ["TestHeadersWithEndStreamLeavesTheStreamHalfClosed"],
    ),
    (
        "RecvWindow answers with a new window every time, so what it reports is never what was spent",
        """func (s *Stream) RecvWindow() *flow.Window { return s.recv }""",
        """func (s *Stream) RecvWindow() *flow.Window { return flow.NewStreamWindow(s.id, flow.InitialWindowSize) }""",
        [
            "TestPaddedDataIsFlowControlledByItsWholeLength",
            "TestDataRefusedByAStreamWindowIsStillCountedAgainstTheConnectionWindow",
        ],
    ),
]

breakage.main(SRC, PKG, BREAKS)
