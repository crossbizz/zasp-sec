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
	readHeaderTimeout       = 2 * time.Second
	readTimeout             = 2 * time.Second
	writeTimeout            = 2 * time.Second
	idleTimeout             = 30 * time.Second
	maxHeaderBytes          = 4 * 1024
	shutdownTimeout         = 5 * time.Second
	defaultReadyInterval    = 5 * time.Second
	defaultReadyMaxInterval = time.Minute
)

var (
	ErrInvalidConfig  = errors.New("invalid health server configuration")
	ErrInvalidRuntime = errors.New("invalid health server runtime")
)

type Config struct {
	Service          string
	Version          string
	ReadyCheck       func(context.Context) bool
	ReadyInterval    time.Duration
	ReadyMaxInterval time.Duration
	Metrics          func() string
}

type Server struct {
	handler          *health.Handler
	httpServer       *http.Server
	shutdownTimeout  time.Duration
	used             atomic.Bool
	serve            func(net.Listener) error
	shutdown         func(context.Context) error
	readyCheck       func(context.Context) bool
	readyInterval    time.Duration
	readyMaxInterval time.Duration
}

func New(config Config) (*Server, error) {
	if config.ReadyInterval == 0 {
		config.ReadyInterval = defaultReadyInterval
	}
	if config.ReadyMaxInterval == 0 {
		config.ReadyMaxInterval = defaultReadyMaxInterval
	}
	if config.ReadyInterval < 100*time.Millisecond || config.ReadyMaxInterval < config.ReadyInterval || config.ReadyMaxInterval > 5*time.Minute {
		return nil, ErrInvalidConfig
	}
	handler, err := health.New(health.Config{Service: config.Service, Version: config.Version, Metrics: config.Metrics})
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
		handler:          handler,
		httpServer:       httpServer,
		shutdownTimeout:  shutdownTimeout,
		serve:            httpServer.Serve,
		shutdown:         httpServer.Shutdown,
		readyCheck:       config.ReadyCheck,
		readyInterval:    config.ReadyInterval,
		readyMaxInterval: config.ReadyMaxInterval,
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

	server.handler.SetReady(false)
	serveDone := make(chan struct{})
	shutdownDone := make(chan error, 1)
	probeCtx, cancelProbes := context.WithCancel(ctx)
	probeDone := make(chan struct{})
	go func() {
		runReadyProbes(probeCtx, server.readyInterval, server.readyMaxInterval, server.ready, server.handler.SetReady)
		close(probeDone)
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				cancelProbes()
				<-probeDone
				server.handler.SetReady(false)
				shutdownContext, cancel := context.WithTimeout(context.Background(), server.shutdownTimeout)
				defer cancel()
				shutdownDone <- server.shutdown(shutdownContext)
				return
			case <-serveDone:
				cancelProbes()
				<-probeDone
				shutdownDone <- nil
				return
			}
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

func runReadyProbes(ctx context.Context, interval, maximum time.Duration, check func(context.Context) bool, set func(bool)) {
	if ctx == nil || check == nil || set == nil || interval <= 0 || maximum < interval {
		return
	}
	delay := interval
	for {
		ready := check(ctx)
		set(ready)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			set(false)
			return
		case <-timer.C:
		}
		if ready {
			delay = interval
		} else if delay < maximum {
			delay *= 2
			if delay > maximum {
				delay = maximum
			}
		}
	}
}

func (server *Server) ready(ctx context.Context) (ready bool) {
	if server.readyCheck == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return server.readyCheck(ctx)
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
