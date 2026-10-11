// Package transport exposes only authenticated Studio-to-application HTTP.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/dashboard"
	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
	"github.com/verdantflarehub/verdantflare-app-network/internal/strictjson"
)

type Management interface {
	List(context.Context, identity.IdentityContext) ([]egress.Endpoint, error)
	Get(context.Context, identity.IdentityContext, string) (egress.Endpoint, error)
	Save(context.Context, identity.IdentityContext, string, egress.Input) (egress.Endpoint, error)
	Delete(context.Context, identity.IdentityContext, string) error
	Test(context.Context, identity.IdentityContext, string) (egress.Endpoint, error)
}
type Server struct {
	Identity  identity.Verifier
	Egress    Management
	Assets    *dashboard.Assets
	tokenHash [32]byte
}

func New(verifier identity.Verifier, management Management, assets *dashboard.Assets, serviceToken string) (*Server, error) {
	if verifier == nil || management == nil || len(serviceToken) < 32 || strings.ContainsAny(serviceToken, " \t\r\n") {
		return nil, errors.New("invalid network service configuration")
	}
	return &Server{verifier, management, assets, sha256.Sum256([]byte(serviceToken))}, nil
}
func bearer(value string) string {
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		reply(w, 200, map[string]string{"status": "ready"})
		return
	}
	id := r.Header.Get("X-Request-ID")
	if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil || parsed.String() != id {
		id = uuid.Must(uuid.NewV7()).String()
	}
	w.Header().Set("X-Request-ID", id)
	provided := sha256.Sum256([]byte(bearer(r.Header.Get("Authorization"))))
	if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(provided[:], s.tokenHash[:]) != 1 {
		failure(w, id, identity.Unauthenticated)
		return
	}
	for _, header := range []string{"X-User-Id", "X-Organization-Id", "X-Station-Id"} {
		if len(r.Header.Values(header)) != 1 {
			failure(w, id, identity.Denied)
			return
		}
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(r.Header.Values("Content-Encoding")) != 0 {
		failure(w, id, identity.Invalid)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	actor, err := s.Identity.Verify(ctx, identity.Actor{UserID: r.Header.Get("X-User-Id"), OrganizationID: r.Header.Get("X-Organization-Id"), StationID: r.Header.Get("X-Station-Id")}, id)
	if err != nil {
		failure(w, id, err)
		return
	}
	// Authorize assets too: loading a navigation entry is not a grant.
	if err = egress.Authorize(actor); err != nil {
		failure(w, id, err)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/dashboard/") {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			reply(w, 405, map[string]string{"code": "INVALID_ARGUMENT", "request_id": id})
			return
		}
		if s.Assets == nil {
			failure(w, id, identity.Unavailable)
			return
		}
		var data []byte
		mime := "application/json"
		switch r.URL.Path {
		case "/internal/dashboard/declaration":
			data = s.Assets.Declaration()
		case "/internal/dashboard/index":
			data = s.Assets.Index()
		default:
			if !strings.HasPrefix(r.URL.Path, "/internal/dashboard/assets/") {
				failure(w, id, egress.ErrNotFound)
				return
			}
			var ok bool
			data, mime, ok = s.Assets.File(strings.TrimPrefix(r.URL.Path, "/internal/dashboard/assets/"))
			if !ok {
				failure(w, id, egress.ErrNotFound)
				return
			}
		}
		w.Header().Set("Content-Type", mime)
		w.Write(data)
		return
	}
	const base = "/api/v1/proxies"
	if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
		failure(w, id, egress.ErrNotFound)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, base), "/")
	proxyID := ""
	probe := false
	if len(parts) == 1 && parts[0] == "" {
	} else if len(parts) == 2 && parts[1] != "" {
		proxyID = parts[1]
	} else if len(parts) == 3 && parts[1] != "" && parts[2] == "test" {
		proxyID = parts[1]
		probe = true
	} else {
		failure(w, id, egress.ErrNotFound)
		return
	}
	methods := "GET, POST"
	if proxyID != "" {
		methods = "GET, PUT, DELETE"
	}
	if probe {
		methods = "POST"
	}
	if !strings.Contains(", "+methods+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", methods)
		reply(w, 405, map[string]string{"code": "INVALID_ARGUMENT", "request_id": id})
		return
	}
	if probe {
		var in struct{}
		if decodeBusiness(r.Body, 1024, &in) != nil {
			failure(w, id, identity.Invalid)
			return
		}
		item, err := s.Egress.Test(ctx, actor, proxyID)
		if err != nil {
			failure(w, id, err)
			return
		}
		reply(w, 200, map[string]any{"item": item})
		return
	}
	switch r.Method {
	case "GET":
		if proxyID == "" {
			items, err := s.Egress.List(ctx, actor)
			if err != nil {
				failure(w, id, err)
				return
			}
			reply(w, 200, map[string]any{"items": items})
		} else {
			item, err := s.Egress.Get(ctx, actor, proxyID)
			if err != nil {
				failure(w, id, err)
				return
			}
			reply(w, 200, map[string]any{"item": item})
		}
	case "POST", "PUT":
		if strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/json" {
			failure(w, id, identity.Invalid)
			return
		}
		var in egress.Input
		if decodeBusiness(r.Body, 64<<10, &in) != nil {
			failure(w, id, identity.Invalid)
			return
		}
		item, err := s.Egress.Save(ctx, actor, proxyID, in)
		if err != nil {
			failure(w, id, err)
			return
		}
		status := 200
		if proxyID == "" {
			status = 201
		}
		reply(w, status, map[string]any{"item": item})
	case "DELETE":
		if err := s.Egress.Delete(ctx, actor, proxyID); err != nil {
			failure(w, id, err)
			return
		}
		w.WriteHeader(204)
	}
}

// Preserve H1 optional-field semantics while rejecting duplicate and unknown keys.
// Closed metadata messages use the stronger required-shape decoder separately.
func decodeBusiness(r io.Reader, maximum int64, target any) error {
	data, err := strictjson.ReadValue(r, maximum)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(target)
}

func reply(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func failure(w http.ResponseWriter, id string, err error) {
	code := "SERVICE_UNAVAILABLE"
	status := 503
	switch {
	case errors.Is(err, identity.Invalid):
		code = "INVALID_ARGUMENT"
		status = 400
	case errors.Is(err, identity.Unauthenticated):
		code = "UNAUTHENTICATED"
		status = 401
	case errors.Is(err, identity.Denied):
		code = "PERMISSION_DENIED"
		status = 403
	case errors.Is(err, egress.ErrNotFound):
		code = "NOT_FOUND"
		status = 404
	case errors.Is(err, egress.ErrConflict):
		code = "PROXY_CONFLICT"
		status = 409
	case errors.Is(err, egress.ErrBusy):
		code = "PROBE_BUSY"
		status = 409
	case errors.Is(err, egress.ErrDisabled):
		code = "PROXY_DISABLED_OR_EXPIRED"
		status = 409
	}
	// Never expose backend errors, SQL, internal URLs or credential material.
	reply(w, status, map[string]string{"code": code, "request_id": id})
}
