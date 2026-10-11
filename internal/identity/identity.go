// Package identity verifies the delegated actor with Station Core on each request.
// Application requests require a separate Studio service credential at transport;
// user sessions are never sent to this application.
package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/strictjson"
)

type Fault string

func (f Fault) Error() string { return string(f) }

const (
	Invalid         Fault = "INVALID_ARGUMENT"
	Unauthenticated Fault = "UNAUTHENTICATED"
	Denied          Fault = "PERMISSION_DENIED"
	Unavailable     Fault = "SERVICE_UNAVAILABLE"
)

type IdentityContext struct {
	RequestID         string    `json:"request_id"`
	StationID         string    `json:"station_id"`
	SessionID         string    `json:"session_id"`
	UserID            string    `json:"user_id"`
	Username          string    `json:"username"`
	OrganizationID    string    `json:"organization_id"`
	OrganizationName  string    `json:"organization_name"`
	Roles             []string  `json:"roles"`
	Scopes            []string  `json:"scopes"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	RevocationVersion int64     `json:"revocation_version"`
	PolicyVersion     int64     `json:"policy_version"`
}

// Verifier is the only identity port consumed by the HTTP adapter.
type Actor struct{ UserID, OrganizationID, StationID string }
type Verifier interface {
	Verify(context.Context, Actor, string) (IdentityContext, error)
}
type Core struct {
	endpoint, station, token string
	client                   *http.Client
}

func NewCore(endpoint, station, token string) (*Core, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/api/v1") || !validID(station) || len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("invalid Core identity configuration")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Core{strings.TrimSuffix(strings.TrimRight(endpoint, "/"), "/api/v1"), station, token, &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func validID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
func (c *Core) Verify(ctx context.Context, actor Actor, requestID string) (IdentityContext, error) {
	var out IdentityContext
	if !validID(actor.UserID) || !validID(actor.OrganizationID) || actor.StationID != c.station {
		return out, Denied
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/internal/v1/app-access", bytes.NewBufferString(`{"app_id":"network"}`))
	if err != nil {
		return out, Unavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", actor.UserID)
	req.Header.Set("X-Organization-Id", actor.OrganizationID)
	req.Header.Set("X-Station-Id", actor.StationID)
	req.Header.Set("X-Request-ID", requestID)
	resp, err := c.client.Do(req)
	if err != nil {
		return out, Unavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return out, Denied
	}
	var access struct {
		SchemaVersion  int      `json:"schema_version"`
		AppID          string   `json:"app_id"`
		UserID         string   `json:"user_id"`
		OrganizationID string   `json:"organization_id"`
		StationID      string   `json:"station_id"`
		Roles          []string `json:"roles"`
		Scopes         []string `json:"scopes"`
		RequestID      string   `json:"request_id"`
	}
	if resp.StatusCode != 200 || strictjson.Decode(resp.Body, 64<<10, &access) != nil {
		return out, Unavailable
	}
	if access.SchemaVersion != 1 || access.AppID != "network" || access.StationID != actor.StationID || access.OrganizationID != actor.OrganizationID || access.UserID != actor.UserID || access.RequestID != requestID ||
		!slices.Contains(access.Roles, "admin") || !slices.Contains(access.Scopes, "app:manage") {
		return out, Denied
	}
	out = IdentityContext{StationID: access.StationID, UserID: access.UserID, OrganizationID: access.OrganizationID, Roles: access.Roles, Scopes: access.Scopes, RequestID: requestID}
	return out, nil
}

func (c *Core) Close() { c.client.CloseIdleConnections() }
