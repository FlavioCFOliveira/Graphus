// Package main contains a minimal, dependency-free Bolt 5.x client that speaks the
// protocol directly over any byte stream (here, a Unix domain socket).
//
// The official Neo4j Go driver (github.com/neo4j/neo4j-go-driver) only dials TCP
// host:port targets, so it cannot reach Graphus over a Unix domain socket. This file
// therefore implements just enough of Bolt 5.x + PackStream v1 — by hand, from the
// wire specification — to demonstrate the UDS (IPC) interface: the handshake, HELLO,
// LOGON, RUN, PULL and GOODBYE, plus a complete PackStream decoder for the server's
// SUCCESS / RECORD / FAILURE replies.
//
// Every byte here is faithful to Graphus's own implementation in the `graphus-bolt`
// crate (handshake.rs, framing.rs, message.rs, packstream.rs). It is intentionally
// compact and readable rather than feature-complete: a teaching client, not a driver.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// --- Bolt handshake (graphus-bolt/src/handshake.rs) --------------------------------

// magic is the 4-byte preamble that opens every Bolt connection: 0x60 0x60 0xB0 0x17.
var magic = []byte{0x60, 0x60, 0xB0, 0x17}

// proposal is one 32-bit, range-encoded version proposal: [0x00, range, minor, major].
// We propose Bolt 5.0..=5.4 in slot 1 (major 5, top minor 4, range 4 = four minors
// below 4 are also acceptable) and leave the other three slots empty (all zeroes).
var versionProposals = []byte{
	0x00, 0x04, 0x04, 0x05, // slot 1: 5.0..=5.4
	0x00, 0x00, 0x00, 0x00, // slot 2: unused
	0x00, 0x00, 0x00, 0x00, // slot 3: unused
	0x00, 0x00, 0x00, 0x00, // slot 4: unused
}

// --- PackStream v1 marker bytes (graphus-bolt/src/packstream.rs) -------------------

const (
	mNull    = 0xC0
	mFalse   = 0xC2
	mTrue    = 0xC3
	mFloat64 = 0xC1

	mInt8  = 0xC8
	mInt16 = 0xC9
	mInt32 = 0xCA
	mInt64 = 0xCB

	mTinyString = 0x80 // 0x80..=0x8F: 0..=15 bytes
	mString8    = 0xD0
	mString16   = 0xD1
	mString32   = 0xD2

	mBytes8  = 0xCC
	mBytes16 = 0xCD
	mBytes32 = 0xCE

	mTinyList = 0x90 // 0x90..=0x9F
	mList8    = 0xD4
	mList16   = 0xD5
	mList32   = 0xD6

	mTinyMap = 0xA0 // 0xA0..=0xAF
	mMap8    = 0xD8
	mMap16   = 0xD9
	mMap32   = 0xDA

	mTinyStruct = 0xB0 // 0xB0..=0xBF: 0..=15 fields, followed by a 1-byte signature
)

// --- Bolt message opcodes (graphus-bolt/src/message.rs) ----------------------------

const (
	opHello   = 0x01
	opGoodbye = 0x02
	opRun     = 0x10
	opPull    = 0x3F
	opLogon   = 0x6A

	opSuccess = 0x70
	opRecord  = 0x71
	opIgnored = 0x7E
	opFailure = 0x7F
)

// --- PackStream encoder ------------------------------------------------------------

// packer builds a PackStream payload using the smallest marker that fits each value,
// exactly as Graphus's Packer does.
type packer struct{ buf []byte }

func (p *packer) structHeader(signature byte, fields int) {
	// A Bolt message is a tiny structure: 0xB0|fieldCount, then the signature byte.
	p.buf = append(p.buf, mTinyStruct|byte(fields), signature)
}

func (p *packer) mapHeader(n int) {
	switch {
	case n < 0x10:
		p.buf = append(p.buf, mTinyMap|byte(n))
	case n < 0x100:
		p.buf = append(p.buf, mMap8, byte(n))
	case n < 0x10000:
		p.buf = append(p.buf, mMap16, byte(n>>8), byte(n))
	default:
		p.buf = append(p.buf, mMap32, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func (p *packer) str(s string) {
	n := len(s)
	switch {
	case n < 0x10:
		p.buf = append(p.buf, mTinyString|byte(n))
	case n < 0x100:
		p.buf = append(p.buf, mString8, byte(n))
	case n < 0x10000:
		p.buf = append(p.buf, mString16, byte(n>>8), byte(n))
	default:
		p.buf = append(p.buf, mString32, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	p.buf = append(p.buf, s...)
}

func (p *packer) int(v int64) {
	switch {
	case v >= -16 && v <= 127:
		p.buf = append(p.buf, byte(int8(v))) // tiny int: the byte is the value
	case v >= -128 && v <= 127:
		p.buf = append(p.buf, mInt8, byte(int8(v)))
	case v >= math.MinInt16 && v <= math.MaxInt16:
		p.buf = append(p.buf, mInt16, byte(v>>8), byte(v))
	case v >= math.MinInt32 && v <= math.MaxInt32:
		p.buf = append(p.buf, mInt32, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		p.buf = append(p.buf, mInt64)
		p.buf = append(p.buf, b[:]...)
	}
}

// --- Chunked framing (graphus-bolt/src/framing.rs) ---------------------------------

// writeMessage frames a payload into Bolt chunks (each a 2-byte big-endian length
// header + payload, at most 65535 bytes) terminated by the 0x00 0x00 end marker, and
// writes it to the stream.
func writeMessage(w io.Writer, payload []byte) error {
	var out []byte
	for len(payload) > 0 {
		n := min(len(payload), 0xFFFF)
		out = append(out, byte(n>>8), byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	out = append(out, 0x00, 0x00) // end-of-message marker
	_, err := w.Write(out)
	return err
}

// readMessage reassembles one Bolt message payload from the chunk stream, skipping any
// NOOP keep-alives (a bare 0x00 0x00 with no preceding payload).
func readMessage(r *bufio.Reader) ([]byte, error) {
	var payload []byte
	started := false
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		n := int(hdr[0])<<8 | int(hdr[1])
		if n == 0 {
			if started {
				return payload, nil // end-of-message
			}
			continue // NOOP keep-alive; keep reading for a real message
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		payload = append(payload, chunk...)
		started = true
	}
}

// --- PackStream decoder ------------------------------------------------------------

// structure is a decoded PackStream structure: a signature tag plus its fields. Bolt
// messages and graph entities (Node/Relationship/Path) all arrive as structures.
type structure struct {
	tag    byte
	fields []any
}

// unpacker reads PackStream values from a byte slice.
type unpacker struct {
	b []byte
	i int
}

func (u *unpacker) u8() (byte, error) {
	if u.i >= len(u.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := u.b[u.i]
	u.i++
	return v, nil
}

func (u *unpacker) take(n int) ([]byte, error) {
	if u.i+n > len(u.b) {
		return nil, io.ErrUnexpectedEOF
	}
	v := u.b[u.i : u.i+n]
	u.i += n
	return v, nil
}

// uint reads an n-byte big-endian unsigned length header.
func (u *unpacker) uint(n int) (int, error) {
	b, err := u.take(n)
	if err != nil {
		return 0, err
	}
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	return v, nil
}

// value decodes one PackStream value. Integers become int64, floats float64, strings
// string, lists []any, maps map[string]any, structures *structure, null nil.
func (u *unpacker) value() (any, error) {
	m, err := u.u8()
	if err != nil {
		return nil, err
	}
	switch {
	case m <= 0x7F: // positive tiny int 0..127
		return int64(m), nil
	case m >= 0xF0: // negative tiny int -16..-1
		return int64(int8(m)), nil
	case m >= mTinyString && m <= 0x8F:
		return u.readString(int(m & 0x0F))
	case m >= mTinyList && m <= 0x9F:
		return u.readList(int(m & 0x0F))
	case m >= mTinyMap && m <= 0xAF:
		return u.readMap(int(m & 0x0F))
	case m >= mTinyStruct && m <= 0xBF:
		return u.readStruct(int(m & 0x0F))
	}
	switch m {
	case mNull:
		return nil, nil
	case mTrue:
		return true, nil
	case mFalse:
		return false, nil
	case mFloat64:
		b, err := u.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
	case mInt8:
		b, err := u.u8()
		return int64(int8(b)), err
	case mInt16:
		b, err := u.take(2)
		if err != nil {
			return nil, err
		}
		return int64(int16(binary.BigEndian.Uint16(b))), nil
	case mInt32:
		b, err := u.take(4)
		if err != nil {
			return nil, err
		}
		return int64(int32(binary.BigEndian.Uint32(b))), nil
	case mInt64:
		b, err := u.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case mString8, mString16, mString32:
		n, err := u.uint(lenWidth(m, mString8, mString16))
		if err != nil {
			return nil, err
		}
		return u.readString(n)
	case mList8, mList16, mList32:
		n, err := u.uint(lenWidth(m, mList8, mList16))
		if err != nil {
			return nil, err
		}
		return u.readList(n)
	case mMap8, mMap16, mMap32:
		n, err := u.uint(lenWidth(m, mMap8, mMap16))
		if err != nil {
			return nil, err
		}
		return u.readMap(n)
	case mBytes8, mBytes16, mBytes32:
		n, err := u.uint(lenWidth(m, mBytes8, mBytes16))
		if err != nil {
			return nil, err
		}
		return u.take(n)
	}
	return nil, fmt.Errorf("packstream: unknown marker 0x%02X", m)
}

// lenWidth returns the size in bytes of the length header for an 8/16/32 marker.
func lenWidth(m, m8, m16 byte) int {
	switch m {
	case m8:
		return 1
	case m16:
		return 2
	default:
		return 4
	}
}

func (u *unpacker) readString(n int) (string, error) {
	b, err := u.take(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (u *unpacker) readList(n int) ([]any, error) {
	out := make([]any, 0, n)
	for range n {
		v, err := u.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (u *unpacker) readMap(n int) (map[string]any, error) {
	out := make(map[string]any, n)
	for range n {
		key, err := u.value()
		if err != nil {
			return nil, err
		}
		val, err := u.value()
		if err != nil {
			return nil, err
		}
		ks, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("packstream: map key is not a string (%T)", key)
		}
		out[ks] = val
	}
	return out, nil
}

func (u *unpacker) readStruct(fields int) (*structure, error) {
	tag, err := u.u8()
	if err != nil {
		return nil, err
	}
	vals, err := u.readList(fields)
	if err != nil {
		return nil, err
	}
	return &structure{tag: tag, fields: vals}, nil
}

// --- Bolt session ------------------------------------------------------------------

// Session is a single synchronous Bolt connection over a byte stream.
type Session struct {
	conn    net.Conn
	r       *bufio.Reader
	Version string // negotiated Bolt version, e.g. "5.4"
	Server  string // server agent string from HELLO, e.g. "Graphus/0.0.2"
}

// QueryResult is the outcome of one RUN+PULL: the column names and the rows.
type QueryResult struct {
	Columns []string
	Rows    [][]any
}

// Dial connects to a Unix domain socket and performs the Bolt handshake, negotiating
// the protocol version.
func Dial(socketPath string, timeout time.Duration) (*Session, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	s := &Session{conn: conn, r: bufio.NewReader(conn)}
	if err := s.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) handshake() error {
	if _, err := s.conn.Write(magic); err != nil {
		return err
	}
	if _, err := s.conn.Write(versionProposals); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := io.ReadFull(s.r, reply[:]); err != nil {
		return fmt.Errorf("reading negotiated version: %w", err)
	}
	if reply == [4]byte{0, 0, 0, 0} {
		return fmt.Errorf("server rejected all proposed Bolt versions (5.0–5.4)")
	}
	// Wire form is [0x00, 0x00, minor, major].
	s.Version = fmt.Sprintf("%d.%d", reply[3], reply[2])
	return nil
}

// send frames and writes one request message.
func (s *Session) send(p *packer) error { return writeMessage(s.conn, p.buf) }

// recv reads one response message and decodes it to a structure.
func (s *Session) recv() (*structure, error) {
	payload, err := readMessage(s.r)
	if err != nil {
		return nil, err
	}
	u := unpacker{b: payload}
	v, err := u.value()
	if err != nil {
		return nil, err
	}
	st, ok := v.(*structure)
	if !ok {
		return nil, fmt.Errorf("expected a structure, got %T", v)
	}
	return st, nil
}

// Login performs HELLO then LOGON (basic scheme). The peer-credential gate must
// already have admitted this process's uid (see the UDS auth notes in the README);
// LOGON authenticates the Bolt session's user with a password.
func (s *Session) Login(userAgent, user, password string) error {
	// HELLO { extra: { user_agent } }
	var hello packer
	hello.structHeader(opHello, 1)
	hello.mapHeader(1)
	hello.str("user_agent")
	hello.str(userAgent)
	if err := s.send(&hello); err != nil {
		return err
	}
	resp, err := s.recv()
	if err != nil {
		return err
	}
	if err := expectSuccess(resp, "HELLO"); err != nil {
		return err
	}
	if meta, ok := resp.fields[0].(map[string]any); ok {
		if srv, ok := meta["server"].(string); ok {
			s.Server = srv
		}
	}

	// LOGON { auth: { scheme: "basic", principal, credentials } }
	var logon packer
	logon.structHeader(opLogon, 1)
	logon.mapHeader(3)
	logon.str("scheme")
	logon.str("basic")
	logon.str("principal")
	logon.str(user)
	logon.str("credentials")
	logon.str(password)
	if err := s.send(&logon); err != nil {
		return err
	}
	resp, err = s.recv()
	if err != nil {
		return err
	}
	return expectSuccess(resp, "LOGON")
}

// Run executes one auto-commit query and pulls every row.
func (s *Session) Run(query string, params map[string]any) (*QueryResult, error) {
	// RUN { query, parameters, extra }
	var run packer
	run.structHeader(opRun, 3)
	run.str(query)
	run.mapHeader(len(params))
	for k, v := range params {
		run.str(k)
		packParam(&run, v)
	}
	run.mapHeader(0) // empty extra map
	if err := s.send(&run); err != nil {
		return nil, err
	}
	resp, err := s.recv()
	if err != nil {
		return nil, err
	}
	if err := expectSuccess(resp, "RUN"); err != nil {
		return nil, err
	}
	cols := extractColumns(resp)

	// PULL { extra: { n: -1 } } — fetch all rows.
	var pull packer
	pull.structHeader(opPull, 1)
	pull.mapHeader(1)
	pull.str("n")
	pull.int(-1)
	if err := s.send(&pull); err != nil {
		return nil, err
	}

	result := &QueryResult{Columns: cols}
	for {
		resp, err := s.recv()
		if err != nil {
			return nil, err
		}
		switch resp.tag {
		case opRecord:
			row, _ := resp.fields[0].([]any)
			result.Rows = append(result.Rows, row)
		case opSuccess:
			return result, nil // trailing summary
		case opFailure:
			return nil, failureError(resp)
		default:
			return nil, fmt.Errorf("unexpected response 0x%02X during PULL", resp.tag)
		}
	}
}

// Close sends GOODBYE and closes the socket.
func (s *Session) Close() error {
	var bye packer
	bye.structHeader(opGoodbye, 0)
	_ = s.send(&bye)
	return s.conn.Close()
}

// packParam encodes a query parameter. The demo uses only strings and ints.
func packParam(p *packer, v any) {
	switch x := v.(type) {
	case string:
		p.str(x)
	case int:
		p.int(int64(x))
	case int64:
		p.int(x)
	case bool:
		if x {
			p.buf = append(p.buf, mTrue)
		} else {
			p.buf = append(p.buf, mFalse)
		}
	case nil:
		p.buf = append(p.buf, mNull)
	default:
		p.str(fmt.Sprintf("%v", x)) // fallback: stringify
	}
}

func expectSuccess(resp *structure, stage string) error {
	switch resp.tag {
	case opSuccess:
		return nil
	case opFailure:
		return fmt.Errorf("%s rejected: %w", stage, failureError(resp))
	case opIgnored:
		return fmt.Errorf("%s ignored (connection in FAILED state)", stage)
	default:
		return fmt.Errorf("unexpected response 0x%02X to %s", resp.tag, stage)
	}
}

// failureError turns a FAILURE structure into a Go error carrying code + message.
func failureError(resp *structure) error {
	if meta, ok := resp.fields[0].(map[string]any); ok {
		code, _ := meta["code"].(string)
		msg, _ := meta["message"].(string)
		return fmt.Errorf("%s: %s", code, msg)
	}
	return fmt.Errorf("server FAILURE")
}

// extractColumns reads the "fields" column-name list from a RUN SUCCESS metadata map.
func extractColumns(resp *structure) []string {
	meta, ok := resp.fields[0].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := meta["fields"].([]any)
	if !ok {
		return nil
	}
	cols := make([]string, 0, len(raw))
	for _, c := range raw {
		if s, ok := c.(string); ok {
			cols = append(cols, s)
		} else {
			cols = append(cols, fmt.Sprintf("%v", c))
		}
	}
	return cols
}

// formatRow renders one record's cells for display.
func formatRow(row []any) string {
	parts := make([]string, len(row))
	for i, cell := range row {
		parts[i] = fmt.Sprintf("%v", cell)
	}
	return strings.Join(parts, " | ")
}
