package handoff

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() (Archive, []byte, time.Time) {
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{7}, 32)
	station, org, id, operation := "0199b501-0000-7000-8000-000000000001", "0199b501-0000-7000-8000-000000000002", "0199b501-0000-7000-8000-000000000003", "0199b501-0000-7000-8000-000000000004"
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	nonce := bytes.Repeat([]byte{3}, a.NonceSize())
	encrypted := a.Seal(nonce, nonce, []byte(`{"Username":"sample-user","Password":"sample-secret"}`), []byte(station+":"+org+":"+id))
	endpoint, _ := json.Marshal([]any{"socks5h", "proxy.example", 1080, "sample-user"})
	sum := sha256.Sum256(endpoint)
	expired := now.Add(-time.Minute)
	token := "0199b501-0000-7000-8000-000000000005"
	s := Snapshot{Format: 1, ID: operation, Station: station, FrozenAt: now.Add(-2 * time.Minute), Proxies: []Proxy{{ID: id, Station: station, Organization: org, Name: "Fixture", Protocol: "socks5h", Host: "proxy.example", Port: 1080, Credentials: encrypted, EndpointKey: hex.EncodeToString(sum[:]), Status: "active", Assigned: []string{"consumer-a"}, Revision: 9, Probe: json.RawMessage(`{"status":"passed","extensions":{"counter":9007199254740993}}`), ProbeToken: &token, ProbeUntil: &expired, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-3 * time.Minute)}}, Audits: []Audit{{ID: "0199b501-0000-7000-8000-000000000006", Request: "fixture", User: nil, Organization: &org, Session: nil, Action: "egress.delete", Outcome: "succeeded", CreatedAt: now.Add(-4 * time.Minute)}}}
	archive, _ := s.Archive()
	return archive, key, now
}
func TestArchivePreservesIdentityCiphertextLeaseAndAudit(t *testing.T) {
	a, key, now := fixture()
	if err := a.Validate(key, a.Snapshot.Station, a.Snapshot.ID, now); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "migration.handoff.json")
	if err := Write(file, a); err != nil {
		t.Fatal(err)
	}
	got, err := Read(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = got.Validate(key, a.Snapshot.Station, a.Snapshot.ID, now); err != nil {
		t.Fatal(err)
	}
	if got.Digest != a.Digest || !bytes.Equal(got.Snapshot.Proxies[0].Credentials, a.Snapshot.Proxies[0].Credentials) || *got.Snapshot.Proxies[0].ProbeToken != *a.Snapshot.Proxies[0].ProbeToken || got.Snapshot.Proxies[0].Revision != 9 || got.Snapshot.Audits[0].Session != nil || got.Snapshot.Audits[0].User != nil {
		t.Fatal("handoff changed fixed identity, history or ciphertext")
	}
	data, _ := os.ReadFile(file)
	if bytes.Contains(data, []byte("sample-secret")) {
		t.Fatal("archive disclosed plaintext")
	}
	if err = Write(file, a); !errors.Is(err, ErrConflict) {
		t.Fatal("existing archive overwritten", err)
	}
	reordered := a.Snapshot
	reordered.Proxies = append([]Proxy(nil), a.Snapshot.Proxies...)
	reordered.Proxies[0].Probe = json.RawMessage(`{ "extensions": {"counter": 9007199254740993}, "status": "passed" }`)
	normalized, _ := reordered.Archive()
	if normalized.Digest != a.Digest {
		t.Fatal("JSON order/spacing or large integer changed digest")
	}
}
func TestArchiveRejectsTamperingWrongAADAndActiveLease(t *testing.T) {
	cases := map[string]func(*Archive){
		"station": func(a *Archive) {
			a.Snapshot.Station = "0199b501-0000-7000-8000-000000000090"
			a.Snapshot.Proxies[0].Station = a.Snapshot.Station
		},
		"organization":       func(a *Archive) { a.Snapshot.Proxies[0].Organization = "0199b501-0000-7000-8000-000000000091" },
		"proxy ID":           func(a *Archive) { a.Snapshot.Proxies[0].ID = "0199b501-0000-7000-8000-000000000092" },
		"credentials":        func(a *Archive) { a.Snapshot.Proxies[0].Credentials[13] ^= 1 },
		"endpoint":           func(a *Archive) { a.Snapshot.Proxies[0].Host = "other.example" },
		"revision":           func(a *Archive) { a.Snapshot.Proxies[0].Revision = 0 },
		"duplicate ID":       func(a *Archive) { a.Snapshot.Proxies = append(a.Snapshot.Proxies, a.Snapshot.Proxies[0]) },
		"missing references": func(a *Archive) { a.Snapshot.Proxies[0].Assigned = nil },
		"active lease": func(a *Archive) {
			future := a.Snapshot.FrozenAt.Add(time.Hour)
			a.Snapshot.Proxies[0].ProbeUntil = &future
		},
		"unpaired lease": func(a *Archive) { a.Snapshot.Proxies[0].ProbeToken = nil },
		"foreign audit":  func(a *Archive) { a.Snapshot.Audits[0].Action = "login" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, key, now := fixture()
			mutate(&a)
			a, _ = a.Snapshot.Archive()
			if a.Validate(key, a.Snapshot.Station, a.Snapshot.ID, now) == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
	a, key, now := fixture()
	a.Snapshot.Proxies[0].Note = "changed without digest"
	if a.Validate(key, a.Snapshot.Station, a.Snapshot.ID, now) == nil {
		t.Fatal("accepted mismatched digest")
	}
	a, key, now = fixture()
	key[0] ^= 1
	if a.Validate(key, a.Snapshot.Station, a.Snapshot.ID, now) == nil {
		t.Fatal("accepted wrong original key")
	}
}
func TestArchiveRejectsDuplicateUnknownMissingAndOversizedJSON(t *testing.T) {
	a, _, _ := fixture()
	data, _ := canonical(a)
	bad := []string{
		strings.Replace(string(data), `"format":1`, `"format":1,"format":1`, 1),
		strings.Replace(string(data), `"format":1`, `"format":1,"unexpected":true`, 1),
		strings.Replace(string(data), `"format":1,`, "", 1),
		strings.Replace(string(data), `"format":1`, `"Format":1`, 1),
		string(data) + `{}`,
	}
	for i, value := range bad {
		var got Archive
		if decode(strings.NewReader(value), MaxBytes, &got) == nil {
			t.Fatalf("accepted invalid JSON case %d", i)
		}
	}
	var got Archive
	if decode(bytes.NewReader(data), 20, &got) == nil {
		t.Fatal("size limit ignored")
	}
}
