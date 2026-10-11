package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCoreAccessRevalidatesAndBindsActor(t *testing.T) {
	actor := Actor{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	rid := uuid.NewString()
	core, err := NewCore("http://core.example", actor.StationID, strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	status := 200
	response := map[string]any{"schema_version": 1, "app_id": "network", "user_id": actor.UserID, "organization_id": actor.OrganizationID, "station_id": actor.StationID, "roles": []string{"admin"}, "scopes": []string{"app:read", "app:manage"}, "request_id": rid}
	core.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/internal/v1/app-access" || r.Method != "POST" || string(body) != `{"app_id":"network"}` || r.Header.Get("X-Station-Id") != actor.StationID || r.Header.Get("X-User-Id") != actor.UserID || r.Header.Get("X-Organization-Id") != actor.OrganizationID || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("c", 32) {
			t.Fatal("delegation contract mismatch")
		}
		data, _ := json.Marshal(response)
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})
	for range 2 {
		out, err := core.Verify(context.Background(), actor, rid)
		if err != nil || out.UserID != actor.UserID || out.SessionID != "" {
			t.Fatal("verified actor invalid", err)
		}
	}
	if calls != 2 {
		t.Fatal("authorization was cached")
	}
	response["organization_id"] = uuid.NewString()
	if _, err = core.Verify(t.Context(), actor, rid); err != Denied {
		t.Fatal("mismatched authority accepted")
	}
	response["organization_id"] = actor.OrganizationID
	status = 403
	if _, err = core.Verify(t.Context(), actor, rid); err != Denied {
		t.Fatal("revocation accepted")
	}
	status = 503
	if _, err = core.Verify(t.Context(), actor, rid); err != Unavailable {
		t.Fatal("unavailable authority accepted")
	}
	bad := actor
	bad.StationID = uuid.NewString()
	before := calls
	if _, err = core.Verify(t.Context(), bad, rid); err != Denied || calls != before {
		t.Fatal("scope not rejected before transport")
	}
}
func TestCoreRejectsDuplicateIdentityFields(t *testing.T) {
	actor := Actor{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	core, _ := NewCore("https://core.example", actor.StationID, strings.Repeat("t", 32))
	core.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"schema_version":1,"schema_version":1}`))}, nil
	})
	if _, err := core.Verify(t.Context(), actor, uuid.NewString()); err != Unavailable {
		t.Fatal("duplicate accepted")
	}
}
