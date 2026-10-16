package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
)

const consumerOrg = "0199b501-0000-7000-8000-000000000001"
const consumerProxy = "0199b501-0000-7000-8000-000000000002"
const otherProxy = "0199b501-0000-7000-8000-000000000003"

type consumerStoreFixture struct {
	proxy egress.ConsumerProxy
	err   error
	calls int
}

func (s *consumerStoreFixture) ReadConsumerProxy(_ context.Context, org, id string) (egress.ConsumerProxy, error) {
	s.calls++
	if org != consumerOrg || id != consumerProxy {
		return egress.ConsumerProxy{}, errors.New("foreign request")
	}
	return s.proxy, s.err
}

func consumerFixture(t *testing.T) (*Consumers, *consumerStoreFixture) {
	t.Helper()
	store := &consumerStoreFixture{proxy: egress.ConsumerProxy{
		Endpoint: egress.Endpoint{ID: consumerProxy, Name: "Test proxy", Protocol: "socks5h", Host: "proxy.example.invalid", Port: 1080, Status: "active", Revision: 4},
		Auth:     egress.Credentials{Username: "fixture-user", Password: "fixture-secret"},
	}}
	config := `{"schema_version":1,"grants":[{"app_id":"fal","organization_id":"` + consumerOrg + `","proxy_ids":["` + consumerProxy + `"],"token_env":"NETWORK_CHANNEL_FAL_TOKEN"}]}`
	handler, err := NewConsumers(strings.NewReader(config), func(string) string { return strings.Repeat("c", 40) }, store, strings.Repeat("s", 40))
	if err != nil {
		t.Fatal(err)
	}
	return handler, store
}

func consumerRequest(handler *Consumers, path, body, token, org string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", consumerBase+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Organization-Id", org)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestConsumerProxyListNeverReturnsEndpointOrCredentials(t *testing.T) {
	handler, store := consumerFixture(t)
	w := consumerRequest(handler, "list", `{"schema_version":1}`, strings.Repeat("c", 40), consumerOrg)
	if w.Code != 200 || store.calls != 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code)
	}
	for _, secret := range []string{"fixture-user", "fixture-secret", "proxy.example.invalid", "\"port\""} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("sensitive list projection")
		}
	}
}

func TestConsumerProxyResolverScopeAndFailureIsolation(t *testing.T) {
	for _, scenario := range []string{"ok", "wrong token", "studio token", "other org", "ungranted", "revision", "disabled", "expired", "backend", "duplicate", "extra", "missing", "query"} {
		t.Run(scenario, func(t *testing.T) {
			handler, store := consumerFixture(t)
			token, org, id, revision := strings.Repeat("c", 40), consumerOrg, consumerProxy, 4
			switch scenario {
			case "wrong token":
				token = strings.Repeat("x", 40)
			case "studio token":
				token = strings.Repeat("s", 40)
			case "other org":
				org = otherProxy
			case "ungranted":
				id = otherProxy
			case "revision":
				revision = 3
			case "disabled":
				store.proxy.Status = "off"
			case "expired":
				past := time.Now().Add(-time.Hour)
				store.proxy.ExpiresAt = &past
			case "backend":
				store.err = errors.New("fixture-secret backend details")
			}
			raw, _ := json.Marshal(map[string]any{"schema_version": 1, "proxy_id": id, "revision": revision})
			body, path := string(raw), "resolve"
			switch scenario {
			case "duplicate":
				body = strings.TrimSuffix(body, "}") + `,"revision":4}`
			case "extra":
				body = strings.TrimSuffix(body, "}") + `,"organization_id":"` + org + `"}`
			case "missing":
				body = `{"schema_version":1}`
			case "query":
				path += "?revision=4"
			}
			w := consumerRequest(handler, path, body, token, org)
			if scenario == "ok" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture-secret") {
					t.Fatal("resolver did not return authorized transport")
				}
			} else {
				if w.Code == 200 || strings.Contains(w.Body.String(), "fixture-secret") || strings.Contains(w.Body.String(), "proxy.example.invalid") {
					t.Fatal("unsafe resolver failure")
				}
			}
			if (scenario == "other org" || scenario == "ungranted" || scenario == "wrong token" || scenario == "studio token") && store.calls != 0 {
				t.Fatal("unauthorized store access")
			}
		})
	}
}

func TestConsumerProxyConfigurationRejectsReusedAndAmbiguousGrants(t *testing.T) {
	_, store := consumerFixture(t)
	grant := consumerGrant{AppID: "fal", OrganizationID: consumerOrg, ProxyIDs: []string{consumerProxy}, TokenEnv: "NETWORK_CHANNEL_FAL_TOKEN"}
	for _, scenario := range []string{"valid", "studio reuse", "other app reuse", "duplicate", "bad org", "bad env", "duplicate proxy", "unknown app"} {
		t.Run(scenario, func(t *testing.T) {
			g := grant
			g.ProxyIDs = append([]string(nil), grant.ProxyIDs...)
			grants := []consumerGrant{g}
			studio := strings.Repeat("s", 40)
			switch scenario {
			case "studio reuse":
				studio = strings.Repeat("c", 40)
			case "other app reuse":
				g.AppID = "google"
				grants = append(grants, g)
			case "duplicate":
				grants = append(grants, g)
			case "bad org":
				grants[0].OrganizationID = "invalid"
			case "bad env":
				grants[0].TokenEnv = "NETWORK_STUDIO_TOKEN"
			case "duplicate proxy":
				grants[0].ProxyIDs = append(grants[0].ProxyIDs, consumerProxy)
			case "unknown app":
				grants[0].AppID = "arbitrary"
			}
			raw, _ := json.Marshal(map[string]any{"schema_version": 1, "grants": grants})
			_, err := NewConsumers(strings.NewReader(string(raw)), func(string) string { return strings.Repeat("c", 40) }, store, studio)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("configuration validation", err)
			}
		})
	}
}

func TestConsumerCredentialCannotEnterManagement(t *testing.T) {
	consumers, store := consumerFixture(t)
	management := &management{}
	verifications := 0
	verify := verifyFunc(func(context.Context, identity.Actor, string) (identity.IdentityContext, error) {
		verifications++
		return identity.IdentityContext{}, identity.Denied
	})
	server, err := New(verify, management, nil, strings.Repeat("s", 40))
	if err != nil {
		t.Fatal(err)
	}
	server.Consumers = consumers
	for _, path := range []string{"/api/v1/proxies", "/internal/dashboard/declaration", consumerBase + "list"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"schema_version":1}`))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 40))
		r.Header.Set("X-Organization-Id", consumerOrg)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		want := 401
		if path == consumerBase+"list" {
			want = 200
		}
		if w.Code != want {
			t.Fatal(path, w.Code)
		}
	}
	if management.calls != 0 || verifications != 0 || store.calls != 1 {
		t.Fatal("consumer crossed management boundary")
	}
}
