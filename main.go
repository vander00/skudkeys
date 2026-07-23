package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"skudkey/src/config"
	"skudkey/src/gui"
	"skudkey/src/logging"
	"skudkey/src/runner"
)

func main() {
	os.Exit(run())
}

func run() int {
	log := logging.New(os.Stdout)
	keys := gui.NewKeyLog()

	cfg, settings, warnings, opts, err := config.Load(os.Args[1:])
	if err != nil {
		var se *config.StartupError
		if errors.As(err, &se) {
			log.Error("%s", se.Message)
			if se.Suggestion != "" {
				log.Error("hint: %s", se.Suggestion)
			}
			return se.Code
		}
		log.Error("configuration error: %v", err)
		return config.ExitConfig
	}
	for _, warning := range warnings {
		log.Warn("%s", warning)
	}

	run := runner.New(log, keys.Add)
	server := gui.NewServer(log, keys, run, settings)

	ln, url, err := server.Listen(opts.Port)
	if err != nil {
		log.Error("%v", err)
		return config.ExitRuntime
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(ln, !opts.NoBrowser, url); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	if missing := cfg.Missing(); len(missing) == 0 {
		if err := run.Start(cfg, server.Auth()); err != nil {
			log.Error("could not start: %v", err)
		}
	} else {
		log.Info("not started yet - open Settings and fill in: %v", missing)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := config.ExitOK
	select {
	case <-ctx.Done():
	case <-server.Quit():
	case err := <-serverErr:
		log.Error("web interface stopped: %v", err)
		code = config.ExitRuntime
	}

	log.Info("shutting down")
	_ = ln.Close()
	run.Stop()
	return code
}
