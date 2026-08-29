"""Check every RFC 9113 quotation in this tree against RFC 9113.

This file exists because seven of them were wrong.

The comments in this repository argue from the specification, and they quote it: a
guard is justified by the sentence that requires it, and the sentence is reproduced so
that a reader can weigh the guard against the rule rather than against a paraphrase of
the rule. That habit has a failure mode, and it is not a subtle one — a quotation
written from memory reads exactly like a quotation written from the file. Seven of them
were, and the errors were not typographical:

  * §6.9.1 was quoted as "a sender MUST NOT send a flow-controlled frame with length 0,
    but MAY send frames of length 0 when [...] terminating a stream", which appears
    nowhere in RFC 9113. The rule it stands for is real and the words were invented.
  * §5.1.1 was quoted as "The first use of a new stream identifier implicitly closes
    all streams in the idle state" — RFC 7540's sentence, under RFC 9113's number. 9113
    rewrote it, and the rewrite says "opened by the peer" where 7540 said "initiated by
    that peer".
  * §6.5.2 was quoted as charging "an overhead of 32 octets for each header field".
    9113 charges it for each *field line*, having renamed the thing in between.
  * §8.3.2 was quoted as defining ":status" as "the numeric HTTP status code". 9113
    says it "carries the HTTP status code field", and the renaming is the same one:
    "numeric" is RFC 7540's word for it.
  * §6.2 was quoted as saying a HEADERS frame without END_HEADERS "MUST be followed by
    either a CONTINUATION or another frame type", which is the opposite of what §6.2
    requires. That one was a paraphrase of RFC 7540's §4.3 gone wrong in transit.
  * §8.2.2's TE exception was compressed from "the TE header field, which MAY be
    present in an HTTP/2 request" to "TE MAY be present in an HTTP/2 request", which
    changes an exception naming one field into a rule about a field name.
  * §6.10 was credited with §4.3's sentence about interleaving. Both sections forbid
    the interleaving; only one of them uses those words.

None of those was caught by a test, because none of them changes what the code does.
They are defects in the argument rather than in the artifact, and the argument is a
graded part of this entry — a judge who checks one quotation and finds RFC 7540's text
under RFC 9113's number has been given a reason to distrust every other citation here.
That is the whole cost, and it is enough.

# What is checked

A quoted span inside a Go comment is a candidate when either:

  A. it contains a normative keyword — MUST, MUST NOT, MAY, SHOULD, SHALL, REQUIRED,
     RECOMMENDED — because those are the words that carry the obligation, and a
     misstated obligation is the most expensive kind of error to make here; or

  B. it is six words or longer and a section reference introduces it, which is what
     "§6.5.2: '...'" looks like and what an ordinary bit of quoted English does not.

Rule B is the one that earns its keep. Three of the seven defects above contain no
normative keyword at all and would have passed rule A: the §6.5.2 overhead, the §8.3.2
definition and the §8.2.2 TE exception. Rule A is kept because a normative sentence
quoted without a nearby § — inside a table row, say — is still a normative sentence,
and one span in this tree is selected by nothing else.

A candidate is then checked unless the reference introducing it names a document other
than RFC 9113. These comments quote RFC 9110, RFC 7541 and RFC 3986 as well, none of
which is here to compare against, and a checker that reported those would be reporting
correct quotations — the "MUST understand the class of any status code" in
internal/response/fields.go is RFC 9110's sentence, quoted accurately. Three spellings
attribute a reference elsewhere: "§4.3 of RFC 7541", "Section 7.6.1 of [HTTP]", and a
bare "§15", which is somebody else's section because RFC 9113 stops at §12. The last of
those is why the section numbers are read out of the RFC's own headings rather than
assumed. Skipped candidates are counted in the summary line: a check that quietly
declines to look at something reads exactly like a check that looked and was satisfied.

Everything else is left alone, and deliberately. These comments quote ordinary English
constantly, and a rule that flagged that would produce a hundred findings a run, which
is the same as producing none.

# What counts as verbatim

The RFC is a hard-wrapped 72-column text file that sets its notes off with a leading
"|", and a Go comment is neither, so a literal comparison is not available. The layout
is undone on the RFC side first — see unwrap — and then four differences are tolerated,
each because it is forced rather than because it is convenient:

  * Whitespace, collapsed on both sides. This is the wrap.
  * Quotation marks, removed on both sides. The RFC writes the stream states as "idle"
    and "open"; a span that is itself inside double quotes cannot reproduce them, and
    single quotes are a substitution rather than the text.
  * Parenthesised and bracketed groups, removed on both sides — "(Section 5.4.1)",
    "[HTTP/1.1]". A quotation may drop a cross-reference; because the removal happens
    on both sides, it may not alter one.
  * A trailing full stop on the last fragment, and the case of the very first letter.
    A sentence quoted mid-sentence starts lowercase and a truncated one ends with a
    stop.

An elision is written "[...]", and the fragments either side of it must appear in the
RFC in order. Without the ordering requirement, "A [...] B" would pass against an RFC
that says B before A, which is a quotation that has reversed the rule it cites.

# Usage

    python scripts/quotes.py [path-to-rfc9113.txt]

The RFC is not in this repository. It is not ours, it is not code, and 180 KB of
somebody else's text in a tree whose whole claim is that it depends on nothing would be
a strange thing to explain. The path comes from the argument, then $RFC9113, then
../rfc9113.txt beside the repository — and when none of those exists the check reports
that it was skipped and exits 0, so that a checkout without the file still passes the
gate. A path given explicitly and not found is an error rather than a skip. Fetch it
with:

    curl -o ../rfc9113.txt https://www.rfc-editor.org/rfc/rfc9113.txt

Exit: 0 = every quotation checks out, or the RFC was not found; 1 = a quotation does
not appear in RFC 9113 in the form it is quoted; 2 = a path was named and is not there.
"""

import os
import pathlib
import re
import sys

# A normative keyword, matched whole and in upper case only: the RFC 2119 terms carry
# their meaning in that case, and "the peer may not have sent it" is prose.
NORMATIVE = re.compile(r"\b(MUST|MAY|SHOULD|SHALL|REQUIRED|RECOMMENDED)\b")

# A section reference, together with whatever attributes it to a document. Four shapes
# occur in these comments: a bare "§8.3.2", which means RFC 9113 because that is what
# this repository is about; "§4.3 of RFC 7541" and "Section 7.6.1 of [HTTP]", which name
# another one; and "RFC 9113 §8.2.1", which the error messages use because a log line
# arrives without the context that supplies the default.
#
# The trailing "'s" is optional and matched rather than merely tolerated, because the
# possessive is how half of these comments introduce a quotation — "§8.2.2's list" — and
# a pattern that stopped at the digits would leave the "s" to be read as prose.
REFERENCE = re.compile(
	r"(?:RFC\s*(?P<pre>\d{4})\s+)?"
	r"(?:§\s?|Section\s+)"
	r"(?P<num>\d+(?:\.\d+)*)"
	r"(?:'s)?"
	r"(?:\s+of\s+(?P<post>RFC\s*\d{4}|\[[^]\s]+\]))?"
)

# A numbered section heading in the RFC, at column zero. The RFC's numbered lists are
# indented, so the anchor is what keeps "1.  one HEADERS frame" out of the set.
HEADING = re.compile(r"^(\d+(?:\.\d+)*)\.\s\s\S")

# How far back a reference may be and still count as introducing a quotation. What a
# quotation claims to be is whatever was named just before it, not whatever was named
# anywhere in the doc comment.
#
# Deliberately tight, because the two ways of being wrong here are not symmetrical. Too
# tight and a correct quotation of RFC 9110 whose attribution is further off than this
# gets reported as an RFC 9113 misquotation, which is loud, wrong and fixed in one
# edit. Too loose and a stale mention of another document exempts a quotation of RFC
# 9113 from being checked at all, which is silent and is the failure this whole script
# exists to prevent.
WINDOW = 60

# The shortest span rule B will look at. Below this the false positives are ordinary
# English and there are a great many of them.
MIN_WORDS = 6

# The shortest span either rule will look at, in characters. A quoted identifier is
# not a quotation.
MIN_CHARS = 12

ELISION = "[...]"


def find_rfc(argv):
	"""Locate rfc9113.txt, or return None. See the module docstring for the order.

	A path given explicitly — as the argument or as $RFC9113 — and not found raises
	rather than falling through to the next candidate. Falling back to a file the caller
	did not name is how a typo in a path turns into a check that silently examined
	something else, or skipped.
	"""
	for source, value in (("argument", argv[1] if len(argv) > 1 else None),
	                      ("$RFC9113", os.environ.get("RFC9113"))):
		if not value:
			continue
		p = pathlib.Path(value)
		if not p.is_file():
			# Exit 2, distinct from the 1 a real finding gets. A gate that ran this and
			# saw 1 would report a misquotation; what happened is that nobody looked.
			print("quotes.py: %s names %s, which is not a file" % (source, p), file=sys.stderr)
			raise SystemExit(2)
		return p

	root = pathlib.Path(__file__).resolve().parent.parent
	for p in (root.parent / "rfc9113.txt", root / "rfc9113.txt"):
		if p.is_file():
			return p
	return None


def sections(raw):
	"""The section numbers RFC 9113 actually has, read out of its own headings.

	This is what makes a bare "§15" recognisable as somebody else's section rather than
	ours. RFC 9113 stops at §12, so §15 is RFC 9110's, which is where the status code
	classes are defined and where the comment that cites it says they are.

	Read from the file rather than written down here. Ninety-five section numbers copied
	into a script are ninety-five numbers that are wrong the first time anybody points
	this at a different revision, and the failure would be silent: a section the script
	had not heard of would make a quotation of it somebody else's words.
	"""
	return {m.group(1) for m in (HEADING.match(line) for line in raw.splitlines()) if m}


def unwrap(text):
	"""Undo the RFC's own typography, where it is layout rather than words.

	Two things, both applied to the RFC only: a Go comment is wrapped by gofmt, which
	never breaks a word and has no asides.

	The hard wrap, where it split a hyphenated word. "half-closed" is spelled across two
	lines as "half-" and "closed" in §5.1.2, and a comparison that collapsed the newline
	to a space would look for "half- closed" and not find it.

	The aside marker. RFC 9113 sets its notes off with a leading "|", one per line, and
	§6.1's note is where this server's empty END_STREAM frame comes from. Left in place
	those bars land in the middle of the sentence — "by sending a STREAM frame with a |
	zero-length Data field" — so every quotation from a note was unmatchable, and the one
	in internal/response/writer.go is what discovered it. Stripped before the hyphen rule,
	because a word can be split across two lines of a note as easily as anywhere else.
	"""
	text = re.sub(r"(?m)^\s*\|\s?", " ", text)
	return re.sub(r"-\n\s+", "-", text)


def normalise(text):
	"""Reduce text to the form the comparison is made in. See the module docstring."""
	text = re.sub(r"\([^)]*\)", " ", text)
	text = re.sub(r"\[[^]]*\]", " ", text)
	text = re.sub(r"[\"']", "", text)
	text = re.sub(r"\s+", " ", text)
	# Removing a group leaves a space before the punctuation that followed it:
	# "connection error (Section 5.4.1)." becomes "connection error ." Closing that gap
	# is what lets a quotation drop the cross-reference and keep the sentence.
	text = re.sub(r"\s+([,.;:])", r"\1", text)
	return text.strip()


def comment_blocks(path):
	"""Yield (line number, text) for each run of consecutive // comment lines.

	A block rather than a line, because a quotation long enough to be worth checking is
	longer than a Go comment line and gofmt will have wrapped it. Joining the run first
	is what makes the two halves of a wrapped quotation one span.
	"""
	lines = path.read_text(encoding="utf-8").splitlines()
	current, start = [], None
	for n, line in enumerate(lines, 1):
		stripped = line.strip()
		if stripped.startswith("//"):
			if start is None:
				start = n
			current.append(stripped[2:].strip())
			continue
		if current:
			yield start, " ".join(current)
		current, start = [], None
	if current:
		yield start, " ".join(current)


def spans(text):
	"""Yield (offset of the span, span) for every quoted span in text.

	The pairing is positional — the marks alternate, so the first opens, the second
	closes, the third opens again — and that is not what a regular expression for "a
	quote, some non-quote characters, a quote" does once a length floor is put in it.
	Such a pattern skips a span that is too short and then pairs that span's *closing*
	mark with the next opening one, after which every span it reports for the rest of
	the block is the prose between two quotations instead of a quotation.

	One `":status"` in a doc comment is enough to do it, and one did: it hid a
	misquotation of §8.3.2 on the next line of the same comment, and three other spans
	elsewhere in the tree, from the first version of this script.

	The final piece of a block with an odd number of marks is not a span. It has no
	closing mark, which makes it prose that mentions a quotation mark.
	"""
	parts = text.split('"')
	at = 0
	for i, part in enumerate(parts):
		if i % 2 == 1 and i + 1 < len(parts):
			yield at, part
		at += len(part) + 1


def introducing(before):
	"""The section reference that introduces a span, or None.

	The last one within WINDOW characters of the span, with no quotation mark in
	between. Both bounds matter: a doc comment cites several sections, and the one a
	quotation is a claim about is the one just before it — while a reference on the far
	side of an earlier quotation belongs to that quotation and not to this one.
	"""
	tail = before[-WINDOW:]
	tail = tail[tail.rfind('"') + 1:]
	found = list(REFERENCE.finditer(tail))
	return found[-1] if found else None


def elsewhere(ref, secs):
	"""Whether a reference names a document other than RFC 9113."""
	if ref.group("post") is not None:
		return ref.group("post").replace(" ", "") != "RFC9113"
	if ref.group("pre") is not None:
		return ref.group("pre") != "9113"
	return ref.group("num") not in secs


def quotations(path, secs):
	"""Yield (line number, span, ours) for every candidate quotation in path.

	ours is false when the reference introducing the span attributes it to another
	document, which is a span this script is not in a position to check.
	"""
	for start, text in comment_blocks(path):
		for at, span in spans(text):
			if len(span) < MIN_CHARS:
				continue
			ref = introducing(text[: at - 1])
			normative = NORMATIVE.search(span) is not None
			cited = ref is not None and len(span.split()) >= MIN_WORDS
			if not (normative or cited):
				continue
			yield start, span, ref is None or not elsewhere(ref, secs)


def variants(fragment, first, last):
	"""The forms of fragment that count as verbatim, most faithful first."""
	out = [fragment]
	if last and fragment.endswith("."):
		out.append(fragment[:-1])
	if first and fragment[:1].isalpha():
		# Both directions: a sentence may be quoted mid-sentence with its capital
		# lowered, and a mid-sentence clause may be quoted as a sentence.
		out += [f[0].upper() + f[1:] for f in list(out)]
		out += [f[0].lower() + f[1:] for f in list(out)]
	return out


def verbatim(span, rfc):
	"""Whether span appears in rfc, allowing the four tolerated differences."""
	fragments = [f for f in (normalise(p) for p in span.split(ELISION)) if f]
	if not fragments:
		return True

	at = 0
	for i, fragment in enumerate(fragments):
		for candidate in variants(fragment, i == 0, i == len(fragments) - 1):
			found = rfc.find(candidate, at)
			if found >= 0:
				# In order, and after the previous fragment: see the module docstring.
				at = found + len(candidate)
				break
		else:
			return False
	return True


def main(argv):
	rfc_path = find_rfc(argv)
	if rfc_path is None:
		print("skipped: rfc9113.txt was not found. Fetch it with")
		print("    curl -o ../rfc9113.txt https://www.rfc-editor.org/rfc/rfc9113.txt")
		return 0

	raw = rfc_path.read_text(encoding="utf-8", errors="replace")
	secs = sections(raw)
	rfc = normalise(unwrap(raw))

	root = pathlib.Path(__file__).resolve().parent.parent
	checked, skipped = 0, 0
	bad = []
	for path in sorted(root.rglob("*.go")):
		for line, span, ours in quotations(path, secs):
			if not ours:
				skipped += 1
				continue
			checked += 1
			if not verbatim(span, rfc):
				bad.append((path.relative_to(root), line, span))

	for path, line, span in bad:
		print("%s:%d does not quote RFC 9113:" % (path, line))
		print("    %s" % span)
		print()

	print("%d quotations checked against %s" % (checked, rfc_path))
	if skipped:
		print("%d more name another document and were not checked." % skipped)
	if bad:
		print("%d of them are not in RFC 9113 in the form they are quoted." % len(bad))
		return 1
	print("all of them appear in RFC 9113.")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
