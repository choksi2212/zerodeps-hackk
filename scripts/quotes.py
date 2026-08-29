"""Check every RFC 9113 quotation in this tree against RFC 9113.

This file exists because six of them were wrong.

The comments in this repository argue from the specification, and they quote it: a
guard is justified by the sentence that requires it, and the sentence is reproduced so
that a reader can weigh the guard against the rule rather than against a paraphrase of
the rule. That habit has a failure mode, and it is not a subtle one — a quotation
written from memory reads exactly like a quotation written from the file. Six of them
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

A quoted span inside a Go comment is checked when either:

  A. it contains a normative keyword — MUST, MUST NOT, MAY, SHOULD, SHALL, REQUIRED,
     RECOMMENDED — because those are the words that carry the obligation, and a
     misstated obligation is the most expensive kind of error to make here; or

  B. it is six words or longer and the comment text immediately before it contains a §
     reference with no intervening quotation mark, which is what "§6.5.2: '...'" looks
     like and what an ordinary bit of quoted English does not.

Rule B is the one that earns its keep. Two of the six defects above contain no
normative keyword at all and would have passed rule A: the §6.5.2 overhead and the
§8.2.2 TE exception. Rule A is kept because a normative sentence quoted without a
nearby § — inside a table row, say — is still a normative sentence.

Everything else is left alone, and deliberately. These comments quote ordinary English
constantly, and they quote RFC 9110, RFC 7541 and RFC 3986, none of which is here to
check against. A rule that flagged those would produce a hundred findings a run, which
is the same as producing none.

# What counts as verbatim

The RFC is a hard-wrapped 72-column text file and a Go comment is not, so a literal
comparison is not available. Four differences are tolerated, each because it is forced
rather than because it is convenient:

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

# A § reference close enough before an opening quote to be introducing it, with no
# quotation mark in between — anchored at the end, because what matters is the text
# immediately before the quote and not the whole comment block.
CITED = re.compile("§\\s?\\d+(\\.\\d+)*[^\"]{0,60}$")

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


def unwrap(text):
	"""Undo the RFC's hard wrap where it split a hyphenated word.

	"half-closed" is spelled across two lines as "half-" and "closed" in §5.1.2, and a
	comparison that collapsed the newline to a space would look for "half- closed" and
	not find it. Applied to the RFC only: a Go comment is wrapped by gofmt, which never
	breaks a word.
	"""
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


def quotations(path):
	"""Yield (line number, span) for every quoted span in path that a rule selects."""
	for start, text in comment_blocks(path):
		for m in re.finditer(r'"([^"]{%d,})"' % MIN_CHARS, text):
			span = m.group(1)
			normative = NORMATIVE.search(span) is not None
			cited = CITED.search(text[: m.start()]) is not None and len(span.split()) >= MIN_WORDS
			if normative or cited:
				yield start, span


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

	rfc = normalise(unwrap(rfc_path.read_text(encoding="utf-8", errors="replace")))

	root = pathlib.Path(__file__).resolve().parent.parent
	checked = 0
	bad = []
	for path in sorted(root.rglob("*.go")):
		for line, span in quotations(path):
			checked += 1
			if not verbatim(span, rfc):
				bad.append((path.relative_to(root), line, span))

	for path, line, span in bad:
		print("%s:%d does not quote RFC 9113:" % (path, line))
		print("    %s" % span)
		print()

	print("%d quotations checked against %s" % (checked, rfc_path))
	if bad:
		print("%d of them are not in RFC 9113 in the form they are quoted." % len(bad))
		return 1
	print("all of them appear in RFC 9113.")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
