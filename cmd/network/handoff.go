package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verdantflarehub/verdantflare-app-network/internal/handoff"
	"github.com/verdantflarehub/verdantflare-app-network/migrations"
)

// Never print PostgreSQL errors or connection strings; even a constraint error
// may include confidential row values. Stable labels identify recovery paths.
func safeFailure(err error) string {
	for _, known := range []error{handoff.ErrInvalid, handoff.ErrConflict, handoff.ErrNotFrozen, handoff.ErrLease} {
		if errors.Is(err, known) {
			return "network operation failed: " + known.Error()
		}
	}
	return "network operation failed; verify controlled configuration and database state"
}

func handoffPool(ctx context.Context, name string) (*pgxpool.Pool, error) {
	value := os.Getenv(name)
	if value == "" {
		return nil, errors.New("database configuration missing")
	}
	cfg, e := pgxpool.ParseConfig(value)
	if e != nil {
		return nil, e
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	return pgxpool.NewWithConfig(ctx, cfg)
}
func runHandoff(ctx context.Context, command string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	station, id, file := os.Getenv("NETWORK_STATION_ID"), os.Getenv("NETWORK_HANDOFF_ID"), os.Getenv("NETWORK_HANDOFF_FILE")
	if command == "handoff-freeze-source" {
		pool, e := handoffPool(ctx, "NETWORK_SOURCE_DATABASE_URL")
		if e != nil {
			return e
		}
		defer pool.Close()
		if e = handoff.FreezeSource(ctx, pool, station, id); e != nil {
			return e
		}
		fmt.Println("source write barrier installed; lease drain and read-only export still required")
		return nil
	}
	if command == "handoff-close" {
		pool, e := handoffPool(ctx, "NETWORK_DATABASE_URL")
		if e != nil {
			return e
		}
		defer pool.Close()
		if e = migrations.Verify(ctx, pool, station); e != nil {
			return e
		}
		if e = handoff.Close(ctx, pool); e != nil {
			return e
		}
		fmt.Println("target writer closed; source remains frozen and rollback requires comparison")
		return nil
	}
	if command != "handoff-export" && command != "handoff-verify" && command != "handoff-check" && command != "handoff-import" && command != "handoff-activate" {
		return errors.New("unsupported handoff operation")
	}
	key, e := base64.StdEncoding.DecodeString(os.Getenv("NETWORK_ENCRYPTION_KEY"))
	if e != nil || len(key) != 32 {
		return errors.New("handoff key unavailable")
	}
	if command == "handoff-export" {
		pool, e := handoffPool(ctx, "NETWORK_SOURCE_DATABASE_URL")
		if e != nil {
			return e
		}
		defer pool.Close()
		a, e := handoff.Export(ctx, pool, station, id, key)
		if e != nil {
			return e
		}
		if e = handoff.Write(file, a); e != nil {
			return e
		}
		fmt.Println(handoff.Summary(a, "exported"))
		return nil
	}
	a, e := handoff.Read(file)
	if e != nil {
		return e
	}
	if e = a.Validate(key, station, id, time.Now()); e != nil {
		return e
	}
	// The verify operation returns before any database configuration is read.
	if command == "handoff-verify" {
		fmt.Println(handoff.Summary(a, "verified-offline"))
		return nil
	}
	source, e := handoffPool(ctx, "NETWORK_SOURCE_DATABASE_URL")
	if e != nil {
		return e
	}
	defer source.Close()
	destination, e := handoffPool(ctx, "NETWORK_DATABASE_URL")
	if e != nil {
		return e
	}
	defer destination.Close()
	if e = migrations.Verify(ctx, destination, station); e != nil {
		return e
	}
	state, e := handoff.Execute(ctx, source, destination, a, key, strings.TrimPrefix(command, "handoff-"))
	if e != nil {
		return e
	}
	fmt.Println(handoff.Summary(a, state))
	return nil
}
