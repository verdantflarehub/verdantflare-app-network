package egress

import (
	"context"

	"github.com/google/uuid"
)

// ConsumerProxy stays internal. Credentials can only be projected by the
// separately authenticated resolver, never by ordinary management JSON.
type ConsumerProxy struct {
	Endpoint
	Auth Credentials `json:"-"`
}

// ReadConsumerProxy is used only after a transport grant has authorized this
// exact organization and proxy ID. It does not create assignments or references.
func (s *Service) ReadConsumerProxy(ctx context.Context, organization, id string) (ConsumerProxy, error) {
	var out ConsumerProxy
	for _, value := range []string{organization, id} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return out, ErrNotFound
		}
	}
	p, err := s.scan(s.Pool.QueryRow(ctx, `SELECT `+columns+` FROM network.egress_proxies WHERE proxy_id=$1 AND station_id=$2 AND organization_id=$3`, id, s.StationID, organization), organization)
	if err != nil {
		return out, err
	}
	auth, err := unseal(s.cipher, p.credentials, s.aad(organization, p.ID))
	if err != nil {
		return out, err
	}
	return ConsumerProxy{Endpoint: p, Auth: auth}, nil
}
