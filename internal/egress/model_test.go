package egress

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
)

func TestCredentialRetentionAADAndRedaction(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	cipher, err := newCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	credentials := Credentials{"test-user", "test-password"}
	aad := "station:org:proxy"
	encrypted, err := seal(cipher, credentials, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(credentials.Password)) {
		t.Fatal("clear password stored")
	}
	got, err := unseal(cipher, encrypted, aad)
	if err != nil || got != credentials {
		t.Fatal("credentials lost")
	}
	for _, invalid := range []string{"other:org:proxy", "station:other:proxy", "station:org:other"} {
		if _, err := unseal(cipher, encrypted, invalid); err == nil {
			t.Fatal("AAD substitution accepted")
		}
	}
	encoded, _ := json.Marshal(Endpoint{credentials: encrypted, AuthConfigured: true})
	if bytes.Contains(encoded, encrypted) || bytes.Contains(encoded, []byte("password")) {
		t.Fatal("credentials exposed")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = unseal(cipher, encrypted, aad); err == nil {
		t.Fatal("tamper accepted")
	}
}
func TestManagementScopeBeforeStorage(t *testing.T) {
	u := identity.IdentityContext{StationID: uuid.NewString(), OrganizationID: uuid.NewString(), UserID: uuid.NewString(), Roles: []string{"admin"}, Scopes: []string{"app:manage"}}
	if Authorize(u) != nil {
		t.Fatal("delegated manager rejected")
	}
	for _, change := range []func(*identity.IdentityContext){func(v *identity.IdentityContext) { v.Roles = nil }, func(v *identity.IdentityContext) { v.Scopes = nil }, func(v *identity.IdentityContext) { v.UserID = "" }, func(v *identity.IdentityContext) { v.OrganizationID = uuid.Nil.String() }} {
		v := u
		change(&v)
		s := &Service{StationID: u.StationID}
		if _, err := s.List(t.Context(), v); err != identity.Denied {
			t.Fatal("unauthorized call reached storage")
		}
	}
}
func TestInputAndEndpointBoundaries(t *testing.T) {
	for _, change := range []func(*Input){func(v *Input) { v.Protocol = "ftp" }, func(v *Input) { v.Port = 0 }, func(v *Input) { v.Port = 65536 }, func(v *Input) { v.Host = "x@y" }, func(v *Input) { v.Status = "active" }, func(v *Input) { v.ExpiresAt = "tomorrow" }, func(v *Input) { v.Name = "" }, func(v *Input) { v.ClearAuth = true; value := "x"; v.Username = &value }} {
		v := Input{Name: "proxy", Protocol: "socks5", Host: "example.com", Port: 1080}
		change(&v)
		if _, err := normalize(&v); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "::1", "2001:db8::1", "::ffff:127.0.0.1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("reserved endpoint allowed")
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public endpoint rejected")
	}
}
