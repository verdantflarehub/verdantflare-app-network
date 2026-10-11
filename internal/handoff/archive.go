// Package handoff prepares an explicit, single-writer Core to Network handoff.
// No function is called from a service request or automatic startup.
package handoff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
)

const MaxBytes int64 = 128 << 20

var ErrInvalid = errors.New("HANDOFF_INVALID")
var ErrConflict = errors.New("HANDOFF_CONFLICT")
var ErrNotFrozen = errors.New("HANDOFF_SOURCE_NOT_FROZEN")
var ErrLease = errors.New("HANDOFF_PROBE_LEASE_ACTIVE")

type Proxy struct {
	ID           string          `json:"proxy_id"`
	Station      string          `json:"station_id"`
	Organization string          `json:"organization_id"`
	Name         string          `json:"name"`
	Protocol     string          `json:"protocol"`
	Host         string          `json:"host"`
	Port         int             `json:"port"`
	Credentials  []byte          `json:"credentials"`
	EndpointKey  string          `json:"endpoint_key"`
	Status       string          `json:"status"`
	Tag          string          `json:"tag"`
	Note         string          `json:"note"`
	ExpiresAt    *time.Time      `json:"expires_at"`
	Assigned     []string        `json:"assigned_apps"`
	Revision     int64           `json:"revision"`
	Probe        json.RawMessage `json:"probe"`
	ProbeToken   *string         `json:"probe_token"`
	ProbeUntil   *time.Time      `json:"probe_until"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}
type Audit struct {
	ID           string    `json:"event_id"`
	Request      string    `json:"request_id"`
	User         *string   `json:"user_id"`
	Organization *string   `json:"organization_id"`
	Session      *string   `json:"session_id"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome"`
	CreatedAt    time.Time `json:"created_at"`
}
type Snapshot struct {
	Format   int       `json:"format"`
	ID       string    `json:"handoff_id"`
	Station  string    `json:"station_id"`
	FrozenAt time.Time `json:"frozen_at"`
	Proxies  []Proxy   `json:"proxies"`
	Audits   []Audit   `json:"audit"`
}
type Archive struct {
	Snapshot Snapshot `json:"snapshot"`
	Digest   string   `json:"sha256"`
}

func validID(v string) bool {
	id, e := uuid.Parse(v)
	return e == nil && id != uuid.Nil && id.String() == v
}
func optionalID(v *string) bool { return v == nil || validID(*v) }

// canonical also normalizes opaque probe objects, without float64 rounding.
func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value any
	if e = d.Decode(&value); e != nil {
		return nil, e
	}
	return json.Marshal(value)
}
func fingerprint(s Snapshot) (string, error) {
	b, e := canonical(s)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (s Snapshot) Archive() (Archive, error) { d, e := fingerprint(s); return Archive{s, d}, e }
func (a Archive) Validate(key []byte, station, id string, now time.Time) error {
	s := a.Snapshot
	if len(key) != 32 || s.Format != 1 || !validID(s.ID) || !validID(s.Station) || s.ID != id || s.Station != station || s.FrozenAt.IsZero() || s.FrozenAt.After(now) || s.Proxies == nil || s.Audits == nil || len(s.Proxies) > 10000 || len(s.Audits) > 100000 {
		return ErrInvalid
	}
	d, e := fingerprint(s)
	if e != nil || d != a.Digest {
		return ErrInvalid
	}
	seen := map[string]bool{}
	endpoints := map[string]bool{}
	previous := ""
	for _, p := range s.Proxies {
		if !validID(p.ID) || p.ID <= previous || seen[p.ID] || p.Station != station || !validID(p.Organization) || p.Revision < 1 || p.CreatedAt.IsZero() || p.UpdatedAt.Before(p.CreatedAt) || p.Assigned == nil || len(p.Assigned) > 10000 || !slices.Contains([]string{"pending", "active", "off"}, p.Status) || !optionalID(p.ProbeToken) {
			return ErrInvalid
		}
		if (p.ProbeToken == nil) != (p.ProbeUntil == nil) {
			return ErrInvalid
		}
		if p.ProbeUntil != nil && p.ProbeUntil.After(now) {
			return ErrLease
		}
		if len(p.Credentials) > 4096 || len(p.Probe) > 1<<20 || len(p.Probe) == 0 || !json.Valid(p.Probe) {
			return ErrInvalid
		}
		if string(p.Probe) != "null" {
			var probe map[string]json.RawMessage
			if json.Unmarshal(p.Probe, &probe) != nil || probe == nil {
				return ErrInvalid
			}
		}
		for _, app := range p.Assigned {
			if app == "" || len(app) > 512 || strings.ContainsRune(app, 0) {
				return ErrInvalid
			}
		}
		input := egress.Input{Name: p.Name, Protocol: p.Protocol, Host: p.Host, Port: p.Port, Tag: p.Tag, Note: p.Note}
		if p.ExpiresAt != nil {
			input.ExpiresAt = p.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		if e = egress.VerifyStoredCredentials(key, station, p.Organization, p.ID, p.EndpointKey, input, p.Credentials); e != nil {
			return ErrInvalid
		}
		endpoint := p.Organization + ":" + p.EndpointKey
		if endpoints[endpoint] {
			return ErrInvalid
		}
		endpoints[endpoint] = true
		seen[p.ID] = true
		previous = p.ID
	}
	previous = ""
	seen = map[string]bool{}
	for _, a := range s.Audits {
		if !validID(a.ID) || a.ID <= previous || seen[a.ID] || !optionalID(a.User) || !optionalID(a.Organization) || !optionalID(a.Session) || len(a.Request) < 1 || len(a.Request) > 128 || !strings.HasPrefix(a.Action, "egress.") || !slices.Contains([]string{"succeeded", "denied"}, a.Outcome) || a.CreatedAt.IsZero() {
			return ErrInvalid
		}
		seen[a.ID] = true
		previous = a.ID
	}
	return nil
}
func Read(path string) (Archive, error) {
	var a Archive
	f, e := os.Open(path)
	if e != nil {
		return a, ErrInvalid
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return a, ErrInvalid
	}
	e = decode(f, MaxBytes, &a)
	return a, e
}
func Write(path string, a Archive) error {
	b, e := canonical(a)
	if e != nil || int64(len(b)) > MaxBytes {
		return ErrInvalid
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrConflict
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	return errors.Join(e, closeErr)
}

// Reject missing/unknown/case-mismatched fields, duplicates and excess nesting.
// Null is allowed only where the typed destination round-trip retains it.
func decode(r io.Reader, limit int64, dst any) error {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(b)) > limit || !utf8.Valid(b) {
		return ErrInvalid
	}
	scan := json.NewDecoder(bytes.NewReader(b))
	scan.UseNumber()
	if scanValue(scan, 0) != nil {
		return ErrInvalid
	}
	if _, e = scan.Token(); e != io.EOF {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	out, e := json.Marshal(dst)
	if e != nil {
		return ErrInvalid
	}
	var original, normalized any
	if json.Unmarshal(b, &original) != nil || json.Unmarshal(out, &normalized) != nil || !sameShape(original, normalized) {
		return ErrInvalid
	}
	return nil
}
func sameShape(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !sameShape(v, w) {
				return false
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i, v := range x {
			if !sameShape(v, y[i]) {
				return false
			}
		}
	case string:
		_, ok := b.(string)
		return ok
	case float64:
		_, ok := b.(float64)
		return ok
	case bool:
		_, ok := b.(bool)
		return ok
	default:
		return false
	}
	return true
}
func scanValue(d *json.Decoder, depth int) error {
	if depth > 48 {
		return ErrInvalid
	}
	v, e := d.Token()
	if e != nil {
		return ErrInvalid
	}
	switch v {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			name, ok := k.(string)
			if e != nil || !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if scanValue(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		v, e = d.Token()
		if e != nil || v != json.Delim('}') {
			return ErrInvalid
		}
	case json.Delim('['):
		for d.More() {
			if scanValue(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		v, e = d.Token()
		if e != nil || v != json.Delim(']') {
			return ErrInvalid
		}
	default:
		if _, ok := v.(json.Delim); ok {
			return ErrInvalid
		}
	}
	return nil
}
