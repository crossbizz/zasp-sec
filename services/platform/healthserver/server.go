package healthserver

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
	readHeaderTimeout = 2 * time.Second
	readTimeout       = 2 * time.Second
	writeTimeout      = 2 * time.Second
	idleTimeout       = 30 * time.Second
	maxHeaderBytes    = 4 * 1024
	shutdownTimeout   = 5 * time.Second
)

var (
	ErrInvalidConfig  = errors.New("invalid health server configuration")
	ErrInvalidRuntime = errors.New("invalid health server runtime")
)

type Config struct {
	Service string
	Version string
}

type Server struct {
	handler         *health.Handler
	httpServer      *http.Server
	shutdownTimeout time.Duration
	used            atomic.Bool
	serve           func(net.Listener) error
	shutdown        func(context.Context) error
}

func New(config Config) (*Server, error) {
	handler, err := health.New(health.Config{Service: config.Service, Version: config.Version})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	return &Server{
		handler:         handler,
		httpServer:      httpServer,
		shutdownTimeout: shutdownTimeout,
		serve:           httpServer.Serve,
		shutdown:        httpServer.Shutdown,
	}, nil
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.handler == nil || server.httpServer == nil ||
		server.serve == nil || server.shutdown == nil || server.shutdownTimeout != shutdownTimeout ||
		invalidInterface(ctx) || invalidInterface(listener) {
		return ErrInvalidRuntime
	}
	if !server.used.CompareAndSwap(false, true) {
		return ErrInvalidRuntime
	}
	if ctx.Err() != nil {
		if err := listener.Close(); err != nil {
			return ErrInvalidRuntime
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
			shutdownDone <- server.shutdown(shutdownContext)
		case <-serveDone:
			shutdownDone <- nil
		}
	}()

	serveErr := server.serve(listener)
	server.handler.SetReady(false)
	close(serveDone)
	shutdownErr := <-shutdownDone
	if shutdownErr != nil {
		return ErrInvalidRuntime
	}
	if ctx.Err() != nil && (serveErr == nil || errors.Is(serveErr, http.ErrServerClosed)) {
		return nil
	}
	return ErrInvalidRuntime
}

func invalidInterface(value any) bool {
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
