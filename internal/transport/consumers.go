package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
	"github.com/verdantflarehub/verdantflare-app-network/internal/strictjson"
)

const consumerBase = "/internal/channel-proxies/v1/"

type ConsumerStore interface {
	ReadConsumerProxy(context.Context, string, string) (egress.ConsumerProxy, error)
}

type consumerGrant struct {
	AppID          string   `json:"app_id"`
	OrganizationID string   `json:"organization_id"`
	ProxyIDs       []string `json:"proxy_ids"`
	TokenEnv       string   `json:"token_env"`
}

type resolvedGrant struct {
	consumerGrant
	hash [32]byte
}

type Consumers struct {
	store  ConsumerStore
	grants []resolvedGrant
}

func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func NewConsumers(config io.Reader, lookup func(string) string, store ConsumerStore, studioToken string) (*Consumers, error) {
	var in struct {
		SchemaVersion int             `json:"schema_version"`
		Grants        []consumerGrant `json:"grants"`
	}
	invalid := errors.New("invalid channel proxy consumer configuration")
	if store == nil || lookup == nil || strictjson.Decode(config, 64<<10, &in) != nil || in.SchemaVersion != 1 || len(in.Grants) == 0 || len(in.Grants) > 64 {
		return nil, invalid
	}
	out := &Consumers{store: store}
	studioHash := sha256.Sum256([]byte(studioToken))
	for _, grant := range in.Grants {
		if !slices.Contains([]string{"fal", "google", "grok", "chatgpt"}, grant.AppID) || !canonicalID(grant.OrganizationID) || len(grant.ProxyIDs) == 0 || len(grant.ProxyIDs) > 128 || !regexp.MustCompile(`^NETWORK_CHANNEL_[A-Z][A-Z0-9_]*_TOKEN$`).MatchString(grant.TokenEnv) {
			return nil, invalid
		}
		seen := map[string]bool{}
		for _, id := range grant.ProxyIDs {
			if !canonicalID(id) || seen[id] {
				return nil, invalid
			}
			seen[id] = true
		}
		token := lookup(grant.TokenEnv)
		if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
			return nil, invalid
		}
		hash := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(hash[:], studioHash[:]) == 1 {
			return nil, invalid
		}
		for _, previous := range out.grants {
			if subtle.ConstantTimeCompare(hash[:], previous.hash[:]) == 1 && (previous.AppID != grant.AppID || previous.OrganizationID == grant.OrganizationID) {
				return nil, invalid
			}
		}
		out.grants = append(out.grants, resolvedGrant{grant, hash})
	}
	return out, nil
}

func (s *Consumers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	id := uuid.Must(uuid.NewV7()).String()
	w.Header().Set("X-Request-ID", id)
	if r.URL.Path != consumerBase+"list" && r.URL.Path != consumerBase+"resolve" {
		failure(w, id, egress.ErrNotFound)
		return
	}
	provided := sha256.Sum256([]byte(bearer(r.Header.Get("Authorization"))))
	org := r.Header.Get("X-Organization-Id")
	var authorized *resolvedGrant
	if len(r.Header.Values("Authorization")) == 1 && len(r.Header.Values("X-Organization-Id")) == 1 && canonicalID(org) {
		for i := range s.grants {
			grant := &s.grants[i]
			if subtle.ConstantTimeCompare(provided[:], grant.hash[:]) == 1 && grant.OrganizationID == org {
				authorized = grant
			}
		}
	}
	if authorized == nil {
		failure(w, id, identity.Unauthenticated)
		return
	}
	media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != "POST" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Encoding")) != 0 || mediaErr != nil || media != "application/json" {
		failure(w, id, identity.Invalid)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == consumerBase+"list" {
		var in struct {
			SchemaVersion int `json:"schema_version"`
		}
		if strictjson.Decode(r.Body, 4096, &in) != nil || in.SchemaVersion != 1 {
			failure(w, id, identity.Invalid)
			return
		}
		items := []map[string]any{}
		for _, proxyID := range authorized.ProxyIDs {
			proxy, err := s.store.ReadConsumerProxy(ctx, org, proxyID)
			if errors.Is(err, egress.ErrNotFound) {
				continue
			}
			if err != nil {
				failure(w, id, err)
				return
			}
			items = append(items, map[string]any{"proxy_id": proxy.ID, "name": proxy.Name, "protocol": proxy.Protocol, "status": proxy.Status, "revision": proxy.Revision, "expires_at": proxy.ExpiresAt})
		}
		reply(w, 200, map[string]any{"schema_version": 1, "items": items})
		return
	}
	var in struct {
		SchemaVersion int    `json:"schema_version"`
		ProxyID       string `json:"proxy_id"`
		Revision      int64  `json:"revision"`
	}
	if strictjson.Decode(r.Body, 4096, &in) != nil || in.SchemaVersion != 1 || in.Revision < 1 || !canonicalID(in.ProxyID) {
		failure(w, id, identity.Invalid)
		return
	}
	if !slices.Contains(authorized.ProxyIDs, in.ProxyID) {
		failure(w, id, identity.Denied)
		return
	}
	proxy, err := s.store.ReadConsumerProxy(ctx, org, in.ProxyID)
	if err != nil {
		failure(w, id, err)
		return
	}
	if proxy.Revision != in.Revision {
		failure(w, id, egress.ErrConflict)
		return
	}
	if proxy.Status != "active" || (proxy.ExpiresAt != nil && !proxy.ExpiresAt.After(time.Now())) {
		failure(w, id, egress.ErrDisabled)
		return
	}
	reply(w, 200, map[string]any{"schema_version": 1, "proxy_id": proxy.ID, "revision": proxy.Revision,
		"protocol": proxy.Protocol, "host": proxy.Host, "port": proxy.Port,
		"username": proxy.Auth.Username, "password": proxy.Auth.Password})
}
