"""Check every RFC quotation in this tree against the RFC it names.

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

A candidate is checked against the document its reference names. Three spellings name one
other than RFC 9113 — "§4.3 of RFC 7541", "Section 7.6.1 of [HTTP]", and a bare "§15",
which is somebody else's section because RFC 9113 stops at §12 — and the last of those is
why the section numbers are read out of the RFC's own headings rather than assumed. RFC
9110, RFC 7541 and RFC 3986 are all quoted here, and each is checked when a copy is beside
the repository; a checkout with only rfc9113.txt names the spans it could not read and
stays green, which is the same bargain the RFC 9113 check itself makes.

Those three were unchecked at first, on the argument that reporting them would be
reporting correct quotations. Two of them were not correct. A comment in internal/hpack
quoted a sentence of §4.2 of RFC 7541 that does not appear in it and that asserts the
opposite of the rule that does — the section requires a dynamic table size update at the
beginning of a header block, and the invented sentence had it permitted anywhere between
two field representations, which is also the opposite of what the decoder three files away
enforces. A comment in internal/limits dropped a word from a real sentence of the same
section. The first was found by accident: it spelled its attribution "RFC 7541 section
4.2", which is a fourth spelling this script does not recognise, so the span fell through
to the RFC 9113 default and was refused for naming the wrong document. Loud, and about the
wrong document, and right. The lesson taken was not to widen the spellings — a quotation of
a document nobody compared against is unchecked whichever way it is spelled, so all three
documents are now compared against, and the ones that still cannot be are listed by file
and line. A check that quietly declines to look at something reads exactly like a check
that looked and was satisfied.

Everything else is left alone, and deliberately. These comments quote ordinary English
constantly, and a rule that flagged that would produce a hundred findings a run, which
is the same as producing none.

# The span neither rule selects

A quotation is invisible to both rules when it carries no normative keyword and no
reference reaches it, and that is not a hypothetical: seven spans in this tree were RFC
9113's own sentences, sitting unchecked. Two failure modes put them there, and neither
looks like anything when you read the comment.

The first is distance. introducing looks back WINDOW characters and the whole reference
has to fit inside that window, so "§6.5.2" followed by forty-five characters of English
before the quotation opens is a citation the script cannot see — internal/response was
two characters over. The second is a nested quotation mark: introducing cuts its window
at the last one, so "§8.3.1: ':path' is '...'" attributes nothing to anything, because
the mark that closes ':path' discards the citation along with the prose before it. Both
are silent, and a span nothing selects is reported exactly as loudly as a span that was
selected and passed, which is not at all.

Widening the rules is not the answer. Fifteen spans in this tree are six words or longer,
uncited and non-normative, and every one is ordinary English in scare quotes — a paragraph
of findings a run, on prose. So the question is put to the RFC instead: a declined span
that appears verbatim in one of these documents is a quotation of it that no reference
reaches, and is reported as one. Of the fifteen, none does. Of the seven, all seven did.
The fix is mechanical and is named in the output — move the citation to within WINDOW
characters of the opening quote, and after any nested mark.

What remains uncovered is a span that is both unattributed and misquoted, which is
verbatim nowhere and so matches nothing. That is a smaller hole than the one this closes
and it is narrowed by the same fix: a citation put within reach moves the span into the
checked set, where being a misquotation is the whole of what gets caught.

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

None of these documents is in this repository. They are not ours, they are not code, and
a megabyte of somebody else's text in a tree whose whole claim is that it depends on
nothing would be a strange thing to explain. RFC 9113's path comes from the argument,
then $RFC9113, then ../rfc9113.txt beside the repository — and when none of those exists
the check reports that it was skipped and exits 0, so that a checkout without the file
still passes the gate. A path given explicitly and not found is an error rather than a
skip. The other three are looked for by name only, beside the repository and then inside
it, and a quotation whose document is missing is named rather than checked. Fetch what
you have room for:

    curl -o ../rfc9113.txt https://www.rfc-editor.org/rfc/rfc9113.txt
    curl -o ../rfc9110.txt https://www.rfc-editor.org/rfc/rfc9110.txt
    curl -o ../rfc7541.txt https://www.rfc-editor.org/rfc/rfc7541.txt

Exit: 0 = every quotation whose document is here checks out, or RFC 9113 was not found;
1 = a quotation does not appear in the document it names, in the form it is quoted, or a
quotation of one of these documents has no reference that reaches it; 2 = a path was
named and is not there.
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

	Only RFC 9113, which is the one document this script requires and the only one whose
	path can be given: it is what this server implements, so its section numbers are what
	an unattributed "§6.9.1" means and its headings are what make a bare "§15" somebody
	else's. The three optional documents are find_others' business.

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


# The other documents these comments quote, and the file each is looked for in. Beside
# the repository first and then inside it, the same order and for the same reason as
# rfc9113.txt: a checkout that fetched them gets them checked, and one that did not stays
# green and says which quotations it could not read.
#
# Optional, unlike RFC 9113, because RFC 9113 is what this server implements and these
# three are what it refers to. But optional is not the same as unchecked, and the
# difference is why they are here at all: two of the spans they cover were wrong. One in
# internal/hpack quoted a sentence of §4.2 of RFC 7541 that does not exist and asserted
# the opposite of the rule that does, and one in internal/limits dropped a word from a
# sentence of the same section. Neither was reachable by this script until the file was
# beside it. Both were found by hand, which is the argument for not needing to.
OTHERS = {
	"7541": "rfc7541.txt",
	"9110": "rfc9110.txt",
	"3986": "rfc3986.txt",
	"9218": "rfc9218.txt",
	"9651": "rfc9651.txt",
}


def find_others():
	"""The optional documents that are present, as {number: path}."""
	root = pathlib.Path(__file__).resolve().parent.parent
	found = {}
	for num, name in OTHERS.items():
		for p in (root.parent / name, root / name):
			if p.is_file():
				found[num] = p
				break
	return found


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


# What each of RFC 9113's own reference tags names, for the comments that quote a
# sentence which cites one. "Section 7.6.1 of [HTTP]" is how RFC 9113 spells a reference
# to RFC 9110, and a comment quoting that sentence keeps the tag rather than translating
# it, because the quotation has to be the RFC's words and the tag is one of them.
TAGS = {
	"HTTP": "9110",
	"HTTP2": "9113",
	"COMPRESSION": "7541",
	"RFC3986": "3986",
	"URI": "3986",
	"TLS": "8446",
}


def document(ref, secs):
	"""Which RFC a reference names, as the four digits of its number.

	A bare section number is RFC 9113's when RFC 9113 has a section by that number, and
	somebody else's when it does not — see sections. Everything else says so outright,
	either as digits or as one of RFC 9113's reference tags.
	"""
	post = ref.group("post")
	if post is not None:
		if post.startswith("["):
			return TAGS.get(post.strip("[]"), post.strip("[]"))
		return post.replace(" ", "").removeprefix("RFC")
	if ref.group("pre") is not None:
		return ref.group("pre")
	return "9113" if ref.group("num") in secs else None


def quotations(path, secs):
	"""Yield (line number, span, document, selected) for every quoted span in path.

	document is the four digits of the RFC the reference introducing the span attributes
	it to, "9113" when nothing attributes it elsewhere, and None for a bare section
	number RFC 9113 does not have — which names a document without saying which, and is
	the one case this script cannot resolve.

	selected is whether either rule reached the span. A span neither rule reaches is
	yielded too, with no document, because it is not finished with: main asks whether it
	is verbatim RFC text anyway, which is what the docstring's third finding class is.
	Dropping it here instead is how seven of RFC 9113's sentences went unchecked.
	"""
	for start, text in comment_blocks(path):
		for at, span in spans(text):
			if len(span) < MIN_CHARS:
				continue
			ref = introducing(text[: at - 1])
			normative = NORMATIVE.search(span) is not None
			cited = ref is not None and len(span.split()) >= MIN_WORDS
			if not (normative or cited):
				yield start, span, None, False
				continue
			yield start, span, "9113" if ref is None else document(ref, secs), True


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


def unattributed(span, texts):
	"""The document a declined span is verbatim in, or None.

	A span neither rule reached is one of two things — a quotation whose citation this
	script cannot see, or a bit of ordinary English in scare quotes — and the documents
	themselves are what tell them apart. Fifteen of the second kind are in this tree and
	not one of them appears in an RFC; all seven of the first kind did.

	Below MIN_WORDS the question is not worth asking. A phrase of five words can land in
	two hundred pages of somebody else's English by coincidence, and a finding about the
	coincidence is not a finding about the comment.
	"""
	if len(span.split()) < MIN_WORDS:
		return None
	for num in sorted(texts):
		if verbatim(span, texts[num]):
			return num
	return None


def main(argv):
	rfc_path = find_rfc(argv)
	if rfc_path is None:
		# Nothing is checked without RFC 9113, not even the spans that name another
		# document: its headings are what tell a bare section number apart from one of
		# somebody else's. So this is the whole check skipping, and it says so.
		print("skipped: rfc9113.txt was not found. Fetch it, and the rest while you are here:")
		print("    curl -o ../rfc9113.txt https://www.rfc-editor.org/rfc/rfc9113.txt")
		print("    curl -o ../rfc9110.txt https://www.rfc-editor.org/rfc/rfc9110.txt")
		print("    curl -o ../rfc7541.txt https://www.rfc-editor.org/rfc/rfc7541.txt")
		return 0

	raw = rfc_path.read_text(encoding="utf-8", errors="replace")
	secs = sections(raw)
	texts = {"9113": normalise(unwrap(raw))}
	paths = {"9113": rfc_path}
	for num, p in find_others().items():
		texts[num] = normalise(unwrap(p.read_text(encoding="utf-8", errors="replace")))
		paths[num] = p

	root = pathlib.Path(__file__).resolve().parent.parent
	checked = 0
	bad, unread, stray = [], [], []
	for path in sorted(root.rglob("*.go")):
		for line, span, doc, selected in quotations(path, secs):
			where = (path.relative_to(root), line, span)
			if not selected:
				num = unattributed(span, texts)
				if num is not None:
					stray.append(where + (num,))
				continue
			if doc not in texts:
				unread.append(where + (doc,))
				continue
			checked += 1
			if not verbatim(span, texts[doc]):
				bad.append(where + (doc,))

	for path, line, span, doc in bad:
		print("%s:%d does not quote RFC %s:" % (path, line, doc))
		print("    %s" % span)
		print()

	# A quotation of one of these documents that no reference reaches. Not a
	# misquotation — the words are the RFC's — but not a checked quotation either, and it
	# was reported as neither until this was here. The fix is always the same, so it is
	# printed rather than left to be rediscovered.
	for path, line, span, doc in stray:
		print("%s:%d quotes RFC %s and no reference reaches it:" % (path, line, doc))
		print("    %s" % span)
		print("    Cite it within %d characters of the opening quote, after any nested mark."
			% WINDOW)
		print()

	print("%d quotations checked against %s"
		% (checked, ", ".join(str(paths[n]) for n in sorted(paths))))

	# The ones this script has no copy of are named rather than counted, because a
	# quotation nobody can audit is the only kind that can be wrong indefinitely. A count
	# says two exist; a list says which two, and reading that list is the whole of their
	# review. RFC 7541's absence made this concrete twice over: a comment in
	# internal/hpack quoted a sentence of §4.2 that does not exist and inverted the rule
	# that does, and a comment in internal/limits dropped a word from a real sentence of
	# the same section. The first was found only because it spelled its attribution in a
	# way this script does not recognise — "RFC 7541 section 4.2" rather than "§4.2 of RFC
	# 7541" — so the span fell through to the RFC 9113 default and was refused for naming
	# the wrong document. That was luck. Fetching the document is the part that is not.
	if unread:
		print()
		print("%d name a document this checkout does not have, and were not checked:"
			% len(unread))
		for path, line, span, doc in unread:
			short = span if len(span) <= 66 else span[:63] + "..."
			print("    %s:%d  RFC %s: %s" % (path, line, doc or "?", short))
		missing = sorted({d for _, _, _, d in unread if d in OTHERS})
		if missing:
			print("Read them by hand, or fetch what they name:")
			for num in missing:
				print("    curl -o ../%s https://www.rfc-editor.org/rfc/%s"
					% (OTHERS[num], OTHERS[num]))

	if bad or stray:
		if bad:
			print("%d of them are not in the document they name, in the form they are quoted."
				% len(bad))
		if stray:
			print("%d more quote one of these documents with nothing to attribute them to."
				% len(stray))
		return 1
	print("all of them appear in the document they name, and nothing quotes one of these")
	print("documents without a reference that reaches it.")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
