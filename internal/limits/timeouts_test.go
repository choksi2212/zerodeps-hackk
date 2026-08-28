package limits

import (
	"reflect"
	"testing"
	"time"
)

// timeoutCount is the number of timeouts the design document enumerates. It is
// asserted rather than derived so that adding a seventh timeout fails here, which
// is the cheapest available reminder that the document listing six needs updating
// and that the new one needs a default, a test and a reason.
const timeoutCount = 6

// TestDefaultTimeoutsAreTheDocumentedValues pins the six numbers. A default that
// drifts silently is the same class of problem as a missing default: the server
// still runs, and the property it was chosen for is quietly gone.
func TestDefaultTimeoutsAreTheDocumentedValues(t *testing.T) {
	got := DefaultTimeouts()
	want := Timeouts{
		TLSHandshake:  10 * time.Second,
		Preface:       10 * time.Second,
		Idle:          60 * time.Second,
		Write:         10 * time.Second,
		SettingsAck:   10 * time.Second,
		ShutdownGrace: 5 * time.Second,
	}
	if got != want {
		t.Errorf("DefaultTimeouts()\n got %+v\nwant %+v", got, want)
	}
}

// TestTimeoutsFieldCount is the tripwire for a field added without a default.
// Without it, a new timeout would default to zero, WithDefaults would leave it
// zero, and every connection would carry a deadline that had already expired.
func TestTimeoutsFieldCount(t *testing.T) {
	if got := reflect.TypeFor[Timeouts]().NumField(); got != timeoutCount {
		t.Errorf("Timeouts has %d fields, want %d; a new timeout needs an entry in "+
			"DefaultTimeouts, a case in WithDefaults, and a line in the design "+
			"document's timeout table", got, timeoutCount)
	}
}

// distinctDefaults is a Timeouts whose fields are all different from each other,
// for testing which field a value was filled from. The real defaults cannot answer
// that question: four of the six are ten seconds.
func distinctDefaults() Timeouts {
	var d Timeouts
	v := reflect.ValueOf(&d).Elem()
	for i := range v.NumField() {
		// 1ms, 2ms, 3ms… — distinct, positive, and short enough that a value
		// leaking into a real timeout would fail a test rather than slow one down.
		v.Field(i).SetInt(int64(time.Duration(i+1) * time.Millisecond))
	}
	return d
}

// TestDistinctDefaultsAreDistinct is a check on the fixture rather than on the
// package. Every test below it is only as good as the values being different, and
// a fixture that quietly produced duplicates would make those tests pass for no
// reason at all.
func TestDistinctDefaultsAreDistinct(t *testing.T) {
	d := distinctDefaults()
	v := reflect.ValueOf(d)
	typ := v.Type()
	seen := map[time.Duration]string{}
	for i := range typ.NumField() {
		got := time.Duration(v.Field(i).Int())
		if got <= 0 {
			t.Errorf("%s = %v, want a positive duration", typ.Field(i).Name, got)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%s and %s are both %v; the fixture must give every field a "+
				"different value", other, typ.Field(i).Name, got)
		}
		seen[got] = typ.Field(i).Name
	}
}

// TestWithDefaultsUsesDefaultTimeouts pins the seam: withDefaultsFrom is only
// worth having if the exported method is exactly it applied to the real defaults.
// Without this, the tests below could be verifying a code path the server never
// takes.
func TestWithDefaultsUsesDefaultTimeouts(t *testing.T) {
	cases := []Timeouts{
		{},
		{Idle: time.Millisecond},
		{TLSHandshake: -1},
		DefaultTimeouts(),
	}
	for _, in := range cases {
		want := in.withDefaultsFrom(DefaultTimeouts())
		if got := in.WithDefaults(); got != want {
			t.Errorf("%+v: WithDefaults()\n got %+v\nwant %+v", in, got, want)
		}
	}
}

// TestWithDefaultsFillsEveryField walks the struct by reflection rather than
// naming the fields, so a field added without a corresponding case in
// withDefaultsFrom fails here even though this test was written before that field
// existed.
//
// Naming the fields would defeat the point: the bug being guarded against is
// forgetting a field, and a test that lists the fields is written by the same
// forgetting hand.
func TestWithDefaultsFillsEveryField(t *testing.T) {
	filled := reflect.ValueOf(Timeouts{}.WithDefaults())
	typ := filled.Type()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type != reflect.TypeFor[time.Duration]() {
			t.Errorf("field %s is %s, not time.Duration; this test only knows how to "+
				"check durations, so a field of another type needs its own check",
				field.Name, field.Type)
			continue
		}
		if d := time.Duration(filled.Field(i).Int()); d <= 0 {
			t.Errorf("%s = %v after WithDefaults on a zero Timeouts, want a positive "+
				"duration; withDefaultsFrom is missing a case for it", field.Name, d)
		}
	}
}

// TestWithDefaultsFillsEachFieldFromItsOwn is the test the real defaults cannot
// express. Filling SettingsAck from d.Write is a plausible copy-paste slip that
// produces the correct number, since both defaults are ten seconds; against
// distinct values it produces the wrong one.
func TestWithDefaultsFillsEachFieldFromItsOwn(t *testing.T) {
	d := distinctDefaults()
	got := reflect.ValueOf(Timeouts{}.withDefaultsFrom(d))
	want := reflect.ValueOf(d)
	typ := want.Type()
	for i := range typ.NumField() {
		if got.Field(i).Int() != want.Field(i).Int() {
			t.Errorf("%s = %v, want %v; it was filled from a different field's default",
				typ.Field(i).Name,
				time.Duration(got.Field(i).Int()),
				time.Duration(want.Field(i).Int()))
		}
	}
}

// TestWithDefaultsKeepsOverrides is the other half: filling in the gaps must not
// overwrite what the caller asked for. Tests inject short timeouts, and a
// WithDefaults that ignored them would make the connection tests wait a minute
// each — or, worse, pass for the wrong reason.
func TestWithDefaultsKeepsOverrides(t *testing.T) {
	// Every field set, and to values a default would never produce.
	custom := Timeouts{
		TLSHandshake:  101 * time.Millisecond,
		Preface:       102 * time.Millisecond,
		Idle:          103 * time.Millisecond,
		Write:         104 * time.Millisecond,
		SettingsAck:   105 * time.Millisecond,
		ShutdownGrace: 106 * time.Millisecond,
	}
	if got := custom.WithDefaults(); got != custom {
		t.Errorf("WithDefaults overwrote a fully specified Timeouts\n got %+v\nwant %+v",
			got, custom)
	}
}

// TestWithDefaultsFillsOneFieldAtATime checks each field independently, because a
// withDefaultsFrom that assigned to the wrong field would still pass both tests
// above: the all-zero case fills everything and the all-set case touches nothing.
func TestWithDefaultsFillsOneFieldAtATime(t *testing.T) {
	const marker = 999 * time.Millisecond
	d := distinctDefaults()
	typ := reflect.TypeFor[Timeouts]()

	for i := range typ.NumField() {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			// One field set to the marker, the rest left zero.
			var in Timeouts
			reflect.ValueOf(&in).Elem().Field(i).SetInt(int64(marker))

			out := reflect.ValueOf(in.withDefaultsFrom(d))
			defaults := reflect.ValueOf(d)
			for j := range typ.NumField() {
				got := time.Duration(out.Field(j).Int())
				want := time.Duration(defaults.Field(j).Int())
				if j == i {
					want = marker
				}
				if got != want {
					t.Errorf("with only %s set, %s = %v, want %v",
						name, typ.Field(j).Name, got, want)
				}
			}
		})
	}
}

// TestWithDefaultsRejectsNonPositiveDurations covers the values a configuration
// mistake produces. A negative duration is the dangerous one: net.Conn treats a
// deadline in the past as already expired, so a stray minus sign would make every
// read fail instantly and the server would look broken rather than misconfigured.
func TestWithDefaultsRejectsNonPositiveDurations(t *testing.T) {
	bad := []time.Duration{
		0,
		-1,
		-1 * time.Nanosecond,
		-1 * time.Hour,
		time.Duration(-1 << 63), // the most negative duration there is
	}
	typ := reflect.TypeFor[Timeouts]()
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		for _, value := range bad {
			var in Timeouts
			reflect.ValueOf(&in).Elem().Field(i).SetInt(int64(value))
			got := time.Duration(reflect.ValueOf(in.WithDefaults()).Field(i).Int())
			want := time.Duration(reflect.ValueOf(DefaultTimeouts()).Field(i).Int())
			if got != want {
				t.Errorf("%s = %v took %v as a configuration, want the default %v",
					name, value, got, want)
			}
		}
	}
}

// TestWithDefaultsDoesNotMutateItsReceiver checks the value semantics the method
// signature promises. A pointer receiver here would let one connection's
// configuration change another's, and the two would be indistinguishable in a log.
func TestWithDefaultsDoesNotMutateItsReceiver(t *testing.T) {
	original := Timeouts{Idle: 5 * time.Millisecond}
	kept := original
	_ = original.WithDefaults()
	if original != kept {
		t.Errorf("WithDefaults mutated its receiver\n got %+v\nwant %+v", original, kept)
	}
}

// TestWithDefaultsIsIdempotent guards against a WithDefaults that adjusts values
// rather than only filling absent ones. Applying it twice happens in practice —
// a server defaults its configuration, then a connection defaults it again — and
// the second application must be a no-op.
func TestWithDefaultsIsIdempotent(t *testing.T) {
	cases := []Timeouts{
		{},
		DefaultTimeouts(),
		{Idle: time.Millisecond},
		{TLSHandshake: -1, Write: time.Hour},
	}
	for _, in := range cases {
		once := in.WithDefaults()
		if twice := once.WithDefaults(); twice != once {
			t.Errorf("WithDefaults(%+v) is not idempotent\n once %+v\ntwice %+v",
				in, once, twice)
		}
	}
}

// TestTimeoutOrdering asserts the relations between the defaults, which are what
// make the errors they produce distinguishable.
//
// These are not style preferences. Every one of these timers starts at roughly the
// same moment — the connection opening — so if the idle timeout were the shortest,
// it would fire first and every one of the specific diagnoses below it would become
// unreachable. h2spec's §6.5.3 case wants SETTINGS_TIMEOUT specifically, and would
// see a closed connection with no GOAWAY instead.
func TestTimeoutOrdering(t *testing.T) {
	d := DefaultTimeouts()
	relations := []struct {
		shorter     time.Duration
		longer      time.Duration
		shorterName string
		longerName  string
		why         string
	}{
		{
			shorterName: "TLSHandshake", shorter: d.TLSHandshake,
			longerName: "Idle", longer: d.Idle,
			why: "a peer that stalls in the handshake must be closed as a handshake " +
				"failure, not swept up by the idle timeout",
		},
		{
			shorterName: "Preface", shorter: d.Preface,
			longerName: "Idle", longer: d.Idle,
			why: "a peer that never sends the preface is diagnosed as such (§3.4), " +
				"which requires the preface bound to be reached first",
		},
		{
			shorterName: "SettingsAck", shorter: d.SettingsAck,
			longerName: "Idle", longer: d.Idle,
			why: "§6.5.3 requires SETTINGS_TIMEOUT specifically, so the ack bound " +
				"must be reached before the connection is closed as idle",
		},
		{
			shorterName: "ShutdownGrace", shorter: d.ShutdownGrace,
			longerName: "Idle", longer: d.Idle,
			why: "shutdown must not wait longer for a stream to finish than the " +
				"connection would have been held open anyway",
		},
	}
	for _, r := range relations {
		if r.shorter >= r.longer {
			t.Errorf("%s (%v) must be shorter than %s (%v): %s",
				r.shorterName, r.shorter, r.longerName, r.longer, r.why)
		}
	}
}

// TestDefaultTimeoutsArePlausible bounds the defaults from both sides. The upper
// bound is the point of the package: a timeout of an hour is a timeout in name
// only. The lower bound is for the client on a bad mobile network, who must not be
// disconnected mid-handshake.
func TestDefaultTimeoutsArePlausible(t *testing.T) {
	const (
		floor   = 1 * time.Second
		ceiling = 5 * time.Minute
	)
	v := reflect.ValueOf(DefaultTimeouts())
	typ := v.Type()
	for i := range typ.NumField() {
		d := time.Duration(v.Field(i).Int())
		if d < floor || d > ceiling {
			t.Errorf("%s = %v, want between %v and %v; outside that range it is "+
				"either hostile to a slow client or not a bound at all",
				typ.Field(i).Name, d, floor, ceiling)
		}
	}
}
