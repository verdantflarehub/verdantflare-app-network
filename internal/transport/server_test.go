package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
)

type verifyFunc func(context.Context, identity.Actor, string) (identity.IdentityContext, error)

func (f verifyFunc) Verify(c context.Context, a identity.Actor, id string) (identity.IdentityContext, error) {
	return f(c, a, id)
}

type management struct {
	calls int
	input egress.Input
}

func (m *management) List(context.Context, identity.IdentityContext) ([]egress.Endpoint, error) {
	m.calls++
	return []egress.Endpoint{}, nil
}
func (m *management) Get(context.Context, identity.IdentityContext, string) (egress.Endpoint, error) {
	m.calls++
	return egress.Endpoint{}, nil
}
func (m *management) Save(_ context.Context, _ identity.IdentityContext, _ string, in egress.Input) (egress.Endpoint, error) {
	m.calls++
	m.input = in
	return egress.Endpoint{}, nil
}
func (m *management) Delete(context.Context, identity.IdentityContext, string) error {
	m.calls++
	return nil
}
func (m *management) Test(context.Context, identity.IdentityContext, string) (egress.Endpoint, error) {
	m.calls++
	return egress.Endpoint{}, nil
}
func TestServiceAndLiveAuthorityRequired(t *testing.T) {
	user, org, station := uuid.NewString(), uuid.NewString(), uuid.NewString()
	calls := 0
	denied := false
	m := &management{}
	verify := verifyFunc(func(_ context.Context, a identity.Actor, rid string) (identity.IdentityContext, error) {
		calls++
		if a.UserID != user || a.OrganizationID != org || a.StationID != station {
			t.Fatal("actor binding lost")
		}
		if denied {
			return identity.IdentityContext{}, identity.Denied
		}
		return identity.IdentityContext{UserID: user, OrganizationID: org, StationID: station, RequestID: rid, Roles: []string{"admin"}, Scopes: []string{"app:manage"}}, nil
	})
	s, _ := New(verify, m, nil, strings.Repeat("s", 32))
	call := func(method, path, token, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", token)
		r.Header.Set("X-User-Id", user)
		r.Header.Set("X-Organization-Id", org)
		r.Header.Set("X-Station-Id", station)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	if call("GET", "/api/v1/proxies", "", "") != 401 || calls != 0 || m.calls != 0 {
		t.Fatal("bare actor headers accepted")
	}
	token := "Bearer " + strings.Repeat("s", 32)
	if call("GET", "/api/v1/proxies", token, "") != 200 || calls != 1 || m.calls != 1 {
		t.Fatal("authorized request failed")
	}
	denied = true
	if call("GET", "/api/v1/proxies", token, "") != 403 || m.calls != 1 {
		t.Fatal("revocation bypass")
	}
	denied = false
	if call("POST", "/api/v1/proxies", token, `{"name":"x","name":"y"}`) != 400 || m.calls != 1 {
		t.Fatal("duplicate input accepted")
	}
	if call("POST", "/api/v1/proxies", token, `{"name":"x","target":"https://bad.example"}`) != 400 || m.calls != 1 {
		t.Fatal("unknown input accepted")
	}
	if call("POST", "/api/v1/proxies/"+uuid.NewString()+"/test", token, `{"target":"https://bad.example"}`) != 400 {
		t.Fatal("arbitrary probe target accepted")
	}
	if call("GET", "/api/v1/proxies?url=https://bad.example", token, "") != 400 {
		t.Fatal("query not rejected")
	}
	if call("PATCH", "/api/v1/proxies", token, "") != 405 {
		t.Fatal("method not rejected")
	}
	if call("GET", "/internal/dashboard/declaration", token, "") != 503 {
		t.Fatal("missing artifact not rejected")
	}
	if call("GET", "/healthz", "", "") != http.StatusOK {
		t.Fatal("health check failed")
	}
	if call("POST", "/api/v1/proxies", token, `{"name":"x","protocol":"socks5","host":"example.com","port":1080,"tag":"","note":"","expires_at":"","clear_auth":false,"revision":0}`) != 201 {
		t.Fatal("explicit empty optional H1 fields lost compatibility")
	}
}
