package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verdantflarehub/verdantflare-app-network/internal/buildinfo"
	"github.com/verdantflarehub/verdantflare-app-network/internal/dashboard"
	"github.com/verdantflarehub/verdantflare-app-network/internal/egress"
	"github.com/verdantflarehub/verdantflare-app-network/internal/identity"
	"github.com/verdantflarehub/verdantflare-app-network/internal/transport"
	"github.com/verdantflarehub/verdantflare-app-network/migrations"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(safeFailure(err))
	}
}
func run() error {
	if len(os.Args) != 2 {
		return errors.New("expected a single operation")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if strings.HasPrefix(os.Args[1], "handoff-") {
		return runHandoff(ctx, os.Args[1])
	}
	if os.Args[1] != "serve" && os.Args[1] != "migrate" && os.Args[1] != "activate-fresh" {
		return errors.New("unsupported operation")
	}
	station := os.Getenv("NETWORK_STATION_ID")
	configuration, err := pgxpool.ParseConfig(os.Getenv("NETWORK_DATABASE_URL"))
	if err != nil {
		return err
	}
	if os.Getenv("NETWORK_DATABASE_URL") == "" {
		return errors.New("database configuration required")
	}
	configuration.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		return err
	}
	defer pool.Close()
	check, cancel := context.WithTimeout(ctx, 30*time.Second)
	if os.Args[1] == "migrate" {
		defer cancel()
		return migrations.Apply(check, pool, station)
	}
	err = migrations.Verify(check, pool, station)
	cancel()
	if err != nil {
		return err
	}
	if os.Args[1] == "activate-fresh" {
		return migrations.ActivateFresh(ctx, pool)
	}
	if err = migrations.VerifyRuntime(ctx, pool); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("NETWORK_ENCRYPTION_KEY"))
	if err != nil || len(key) != 32 {
		return errors.New("encryption key unavailable")
	}
	prober, err := egress.NewProber(os.Getenv("NETWORK_ALLOWED_INTERNAL"))
	if err != nil {
		return err
	}
	management, err := egress.New(pool, station, key, prober)
	if err != nil {
		return err
	}
	core, err := identity.NewCore(os.Getenv("NETWORK_CORE_URL"), station, os.Getenv("NETWORK_CORE_TOKEN"))
	if err != nil {
		return err
	}
	defer core.Close()
	assetRoot := os.Getenv("NETWORK_DASHBOARD_DIR")
	if assetRoot == "" {
		assetRoot = "/app/dashboard"
	}
	assets, err := dashboard.Load(assetRoot, buildinfo.Version)
	if err != nil {
		return err
	}
	handler, err := transport.New(core, management, assets, os.Getenv("NETWORK_STUDIO_TOKEN"))
	if err != nil {
		return err
	}
	if consumerFile := os.Getenv("NETWORK_CHANNEL_CONSUMERS_FILE"); consumerFile != "" {
		file, err := os.Open(consumerFile)
		if err != nil {
			return errors.New("channel proxy configuration unavailable")
		}
		handler.Consumers, err = transport.NewConsumers(file, os.Getenv, management, os.Getenv("NETWORK_STUDIO_TOKEN"))
		file.Close()
		if err != nil {
			return err
		}
	}
	address := os.Getenv("NETWORK_LISTEN_ADDR")
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
