package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/health"
)

const (
	healthReadHeaderTimeout = 2 * time.Second
	healthReadTimeout       = 2 * time.Second
	healthWriteTimeout      = 2 * time.Second
	healthIdleTimeout       = 30 * time.Second
	healthMaxHeaderBytes    = 4 * 1024
	healthShutdownTimeout   = 5 * time.Second
)

var (
	errInvalidHealthConfig  = errors.New("invalid health server configuration")
	errInvalidHealthRuntime = errors.New("invalid health server runtime")
)

type healthServerConfig struct {
	service string
	version string
}

type healthServer struct {
	handler         *health.Handler
	httpServer      *http.Server
	shutdownTimeout time.Duration
	used            atomic.Bool
	serve           func(net.Listener) error
	shutdown        func(context.Context) error
}

func newHealthServer(config healthServerConfig) (*healthServer, error) {
	handler, err := health.New(health.Config{Service: config.service, Version: config.version})
	if err != nil {
		return nil, errInvalidHealthConfig
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: healthReadHeaderTimeout,
		ReadTimeout:       healthReadTimeout,
		WriteTimeout:      healthWriteTimeout,
		IdleTimeout:       healthIdleTimeout,
		MaxHeaderBytes:    healthMaxHeaderBytes,
	}
	return &healthServer{
		handler:         handler,
		httpServer:      httpServer,
		shutdownTimeout: healthShutdownTimeout,
		serve:           httpServer.Serve,
		shutdown:        httpServer.Shutdown,
	}, nil
}

func (server *healthServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.handler == nil || server.httpServer == nil ||
		server.serve == nil || server.shutdown == nil || server.shutdownTimeout != healthShutdownTimeout ||
		invalidRuntimeValue(ctx) || invalidRuntimeValue(listener) {
		return errInvalidHealthRuntime
	}
	if !server.used.CompareAndSwap(false, true) {
		return errInvalidHealthRuntime
	}
	if ctx.Err() != nil {
		if err := listener.Close(); err != nil {
			return errInvalidHealthRuntime
		}
		return nil
	}

	server.handler.SetReady(true)
	serveDone := make(chan struct{})
	shutdownDone := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			server.handler.SetReady(false)
			shutdownContext, cancel := context.WithTimeout(context.Background(), server.shutdownTimeout)
			defer cancel()
			shutdownDone <- callHealthShutdown(server.shutdown, shutdownContext)
		case <-serveDone:
			shutdownDone <- nil
		}
	}()

	serveErr := callHealthServe(server.serve, listener)
	server.handler.SetReady(false)
	close(serveDone)
	shutdownErr := <-shutdownDone
	if shutdownErr != nil {
		return errInvalidHealthRuntime
	}
	if ctx.Err() != nil && (serveErr == nil || errors.Is(serveErr, http.ErrServerClosed)) {
		return nil
	}
	return errInvalidHealthRuntime
}

func callHealthServe(serve func(net.Listener) error, listener net.Listener) (result error) {
	defer func() {
		if recover() != nil {
			result = errInvalidHealthRuntime
		}
	}()
	return serve(listener)
}

func callHealthShutdown(shutdown func(context.Context) error, ctx context.Context) (result error) {
	defer func() {
		if recover() != nil {
			result = errInvalidHealthRuntime
		}
	}()
	return shutdown(ctx)
}

func invalidRuntimeValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
