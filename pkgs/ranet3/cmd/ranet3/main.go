// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Command ranet3 connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel speaker. Babel exchanges control
// packets inside ESP. Address and route configuration are external unless the
// file carries a cap.table block, which turns the route reconciler on.
//
// `ranet3 daemon` is the node. Every other subcommand reads a running
// one's control socket; see cli.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/version"
)

// main runs the command tree and turns what it returns into a process status.
// A daemon that refused to start has already said why through the handler an
// operator's log level selects, so its status comes back as an exitCode and is
// not written a second time.
func main() {
	if err := newRoot().Execute(); err != nil {
		if code, ok := errors.AsType[exitCode](err); ok {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// exitCode carries a process status out through cobra's error return, which is
// the only way back to main from a command body.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// options is the daemon's command line after parsing.
type options struct {
	configPath         string
	pprofAddr          string
	metricsAddr        string
	controlPath        string
	contentionProfiles bool
	level              slog.Level
	debugAccess        control.DebugAccess
}

// daemonCommand is the node itself. Its flags are its own rather than the
// root's: a reader's --control names a socket to read and this one names a
// socket to bind, and the two would share a description that fits neither.
//
// run starts the node from the options the flags came to, runDaemon unless a test reads them instead
func daemonCommand(run func(options) int) *cobra.Command {
	var o options
	var logLevel, debugAccess string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the ranet3 node",
		Long: `The node connects to its peers with IKEv2 and ESP, runs a Babel speaker
over those sessions, and writes the routes it learns into a kernel
routing table when the config file asks for it. The config file is TOML,
YAML or JSON, told apart by its extension: .toml, .yaml, .yml or .json.
Most other commands reach the node through its control socket.

The --debug-access flag decides who may use the debug paths that serve
profiles, logs and captures. The value root admits uid 0 and the user
the daemon runs as, group admits everyone who can open the socket, and
off refuses every debug path.

The --pprof flag serves pprof on an address such as 127.0.0.1:6060. A CPU
profile is at /debug/pprof/profile, and this opens one as a flamegraph:

go tool pprof -http=:8081 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'

The --contention-profiles flag adds mutex and blocking profiles while
pprof is served, at a high cost in overhead.`,
		Args: noArguments,
		RunE: func(*cobra.Command, []string) error {
			if err := o.level.UnmarshalText([]byte(logLevel)); err != nil {
				return fmt.Errorf("invalid --log-level %q: log level is one of %s", logLevel, strings.Join(logLevelNames(), ", "))
			}
			if err := o.debugAccess.UnmarshalText([]byte(debugAccess)); err != nil {
				return fmt.Errorf("invalid --debug-access %q: %w", debugAccess, err)
			}
			if code := run(o); code != 0 {
				return exitCode(code)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.configPath, "config", "c", defaultConfig, "Path to the config file")
	f.StringVar(&o.pprofAddr, "pprof", "", "Serve pprof on this address")
	f.BoolVar(&o.contentionProfiles, "contention-profiles", false, "Record lock contention profiles")
	f.StringVar(&o.metricsAddr, "metrics", "", "Serve Prometheus metrics on this address")
	f.StringVar(&o.controlPath, "control", control.DefaultSocket, "Control socket to serve or empty for none")
	f.StringVar(&logLevel, "log-level", defaultLogLevel, "Minimum log level")
	f.StringVar(&debugAccess, "debug-access", string(control.DebugRoot), "Who may use the debug commands")
	cmd.RegisterFlagCompletionFunc("log-level", cobra.FixedCompletions(logLevelNames(), cobra.ShellCompDirectiveNoFileComp))
	cmd.RegisterFlagCompletionFunc("debug-access", cobra.FixedCompletions(control.DebugAccessNames(), cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

// logLevelNames is the levels --log-level takes by name, as slog spells them in lowercase
func logLevelNames() []string {
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	names := make([]string, 0, len(levels))
	for _, level := range levels {
		names = append(names, strings.ToLower(level.String()))
	}
	return names
}

// refuseToStart reports a startup this node will not attempt, at the level an
// operator filters for. The standard logger writes through slog at INFO,
// which --log-level warn and above drop, so every refusal below was a process
// that exited 1 having written nothing at all.
func refuseToStart(err error) int {
	slog.Error("ranet3 is not starting", "err", err)
	return 1
}

// runDaemon is the node's body, in a function of its own so that every
// deferred close runs before the process exits with a status. A failure
// reported only in the log and then exited zero tells a supervisor the node
// stopped cleanly when it did not, and the route withdrawal at shutdown is one
// of the things that reports this way.
func runDaemon(opts options) int {
	configPath, pprofAddr := &opts.configPath, &opts.pprofAddr
	metricsAddr, contentionProfiles := &opts.metricsAddr, &opts.contentionProfiles
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.level})))

	// Set by anything that fails on a goroutine or after runDaemon has
	// committed to a clean shutdown. It returns nonzero if any of them did.
	var failed atomic.Bool

	if *pprofAddr != "" {
		if *contentionProfiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(1)
		}
		go func() {
			log.Printf("pprof listening on http://%s/debug/pprof/", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof: %v", err)
				failed.Store(true)
			}
		}()
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return refuseToStart(err)
	}
	bus := events.New()
	node, err := client.New(cfg, bus)
	if err != nil {
		return refuseToStart(err)
	}
	defer node.Close()
	mesh := node.Mesh
	// The reload verb re-reads the file this daemon was started with, so the
	// socket and SIGHUP ask for the same thing rather than the socket guessing
	// at a default path.
	node.SetConfigPath(*configPath)

	// A separate listener from pprof: a fleet node wants metrics scraped
	// without exposing a profiler, and a profiling run wants the profiler
	// without rewiring monitoring.
	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", node.MetricsHandler())
		server := &http.Server{Addr: *metricsAddr, Handler: mux}
		go func() {
			log.Printf("metrics listening on http://%s/metrics", *metricsAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics: %v", err)
				failed.Store(true)
			}
		}()
		defer server.Close()
	}

	// One registration and one reader, rather than signal.NotifyContext plus a
	// second channel registered after it cancels. Shutdown closes every
	// session with a grace period, withdraws the installed routes and waits
	// for every dialer, and while that is slow an operator pressing Ctrl-C
	// again has nothing to press; the second signal answers that.
	//
	// Registering the second channel only after the first signal leaves a
	// window in which a signal reaches nobody: NotifyContext has stopped
	// reading its own channel and the replacement does not exist yet. Two
	// signals with no gap lose the second there. Registering it up front
	// instead delivers the first signal to both, and then the first Ctrl-C
	// forces an exit rather than shutting down, which is the failure the
	// window was introduced to fix. Reading both from one channel in order has
	// neither: the first cancels, the second forces, and a burst of two is
	// held by the buffer.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchSignals(signals, cancel, func() { os.Exit(1) })

	// SIGHUP reconciles rather than restarts. The registry is rewritten every
	// time any node joins the mesh, and a restart to pick that up would drop
	// every SA this node is carrying.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				if err := node.ReloadFrom(*configPath); err != nil {
					log.Printf("reload: %v", err)
				}
			}
		}
	}()

	// The reconciler is one capability, so a deployment that configures its
	// device externally writes no cap.table and gets none of this.
	var reconciler sync.WaitGroup
	if table := cfg.Cap.Table; table != nil {
		// The half the file could not say is the node's own to answer, so the
		// node answers it; see client.KernelRuntime.
		routes, err := kernel.New(*table, node.KernelRuntime(), mesh.Routes)
		if err != nil {
			return refuseToStart(err)
		}
		reconciler.Go(func() {
			// This error is the withdrawal failing as often as it is the
			// reconcile: routes left behind in the kernel after shutdown are
			// exactly what an operator must not be told was a clean exit.
			if err := routes.Run(ctx); err != nil {
				log.Printf("kernel: %v", err)
				failed.Store(true)
			}
		})
		// The table is read back from the reconciler rather than from the
		// config, which has not had its defaults applied yet and reads zero on
		// a platform that has no tables at all.
		log.Printf("tun device %s ready with %d queues, reconciling its routes into %s",
			mesh.Name, mesh.QueueCount(), routes.Where())
		node.SetKernelStatus(func() control.KernelStatus { return kernelStatus(routes) })
		node.SetReconcilerEnable(routes.SetEnabled)
		node.SetReconcilerTable(routes.SetTable)
	} else {
		log.Printf("tun device %s ready with %d queues, configure its addresses and kernel routes externally",
			mesh.Name, mesh.QueueCount())
	}

	// cap.egress is written or absent the same way, and is built after the
	// reconciler because the two share a shutdown order: the translator
	// withdraws its tables while the tun still exists, as the reconciler
	// withdraws its routes.
	if exit := cfg.Egress(); exit != nil {
		translator, err := egress.New(*exit, egress.Runtime{
			Interface:     mesh.Name,
			MeshAddresses: client.MeshAddresses(cfg),
			Forwarding:    client.Forwarding,
			// Published through the runtime rather than read out of the
			// config, which is how an exit whose rule is not installed
			// withholds its advertisement instead of attracting traffic it
			// would drop. The prefixes are read back from the translator, so
			// this callback only has to say that they changed.
			Announce: func([]netip.Prefix) { node.Republish() },
			Events:   bus,
		})
		if err != nil {
			return refuseToStart(err)
		}
		node.SetEgressAnnounce(translator.Announce)
		node.SetEgressStatus(func() control.EgressStatus { return egressStatus(translator) })
		reconciler.Go(func() {
			// As with the reconciler, this error is the withdrawal failing as
			// often as the pass: a translation rule left in the host's packet
			// filter after shutdown must never be reported to an operator as a
			// clean exit.
			if err := translator.Run(ctx); err != nil {
				log.Printf("egress: %v", err)
				failed.Store(true)
			}
		})
		log.Printf("egress translating for %d prefixes in %s", len(exit.Advertise), translator.Where())
	}

	// The control socket is bound rather than served here, so a path an
	// operator named and this node cannot bind refuses the startup instead of
	// leaving a node nobody has a way to ask anything. The default path is the
	// one case that warns and carries on: it is on without being asked for, so
	// a node whose unit cannot reach /var/run would otherwise stop starting on
	// upgrade over a diagnostic it never requested. --control "" is the opt-out.
	listener, err := serveControl(opts, node, &failed)
	if err != nil {
		return refuseToStart(err)
	}
	if listener != nil {
		defer listener.Close()
	}

	// The reconciler has to finish withdrawing while the TUN still exists,
	// and client.Run destroys it as soon as its own context is done. So the
	// mesh runs on a context canceled only once the reconciler has returned;
	// the signal context still stops both, just in that order.
	meshCtx, stopMesh := context.WithCancel(context.Background())
	defer stopMesh()
	go func() {
		<-ctx.Done()
		bus.Emit("daemon.stopping", "")
		// the subscriptions end as the shutdown starts rather than at exit
		// so every stream writes its closing line while the process still has seconds to run
		bus.Close()
		reconciler.Wait()
		stopMesh()
	}()

	// SIGUSR1 dumps the current mesh route table to the log — the fastest
	// way to see what babel has actually installed without wiring up a
	// separate debug endpoint. Route installs/retractions and neighbor
	// up/down transitions are also logged as they happen.
	dumpRoutes := make(chan os.Signal, 1)
	signal.Notify(dumpRoutes, syscall.SIGUSR1)
	defer signal.Stop(dumpRoutes)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-dumpRoutes:
				routes := mesh.Routes.Debug()
				if len(routes) == 0 {
					log.Printf("routes: (none installed)")
					continue
				}
				log.Printf("routes:")
				for _, r := range routes {
					log.Printf("  %s", r)
				}
			}
		}
	}()

	bus.Emit("daemon.started", "", slog.String("version", version.String()), slog.String("config", *configPath))
	if err := node.Run(meshCtx); err != nil && ctx.Err() == nil {
		log.Printf("client: %v", err)
		failed.Store(true)
	}
	// Whichever side stopped first, stop the other, then let the reconciler
	// finish withdrawing before the process exits.
	cancel()
	reconciler.Wait()
	if failed.Load() {
		return 1
	}
	return 0
}

// debugNode is the node under the --debug-access it was started with
type debugNode struct {
	*client.Client
	access control.DebugAccess
}

func (n debugNode) DebugAccess() control.DebugAccess { return n.access }

// serveControl binds the socket opts names and answers it for node, the debug paths under opts' --debug-access
// a nil listener and no error is a node running without a socket, for the reasons runDaemon gives
func serveControl(opts options, node *client.Client, failed *atomic.Bool) (net.Listener, error) {
	if opts.controlPath == "" {
		return nil, nil
	}
	listener, err := control.Listen(opts.controlPath)
	switch {
	case err != nil && opts.controlPath == control.DefaultSocket:
		slog.Warn("running without a control socket, so the subcommands have nothing to read", "err", err)
		return nil, nil
	case err != nil:
		return nil, err
	}
	go func() {
		log.Printf("control socket listening on %s", opts.controlPath)
		if err := control.Serve(listener, debugNode{node, opts.debugAccess}); err != nil {
			log.Printf("control: %v", err)
			failed.Store(true)
		}
	}()
	return listener, nil
}

// watchSignals starts the shutdown on the first signal and gives up on the
// second. Both come off one channel in order, which keeps a signal from
// reaching nobody; see the registration above.
func watchSignals(signals <-chan os.Signal, cancel context.CancelFunc, force func()) {
	<-signals
	cancel()
	<-signals
	log.Print("second signal, exiting without finishing shutdown")
	force()
}

// kernelStatus is the reconciler as the control surface reports it: what it
// was configured to own and what its last pass did. The configuration half
// comes from the capability the reconciler resolved rather than from the file,
// so the defaults it filled in are the ones reported.
func kernelStatus(routes *kernel.Reconciler) control.KernelStatus {
	table, stats := routes.Table(), routes.Stats()
	return control.KernelStatus{
		Enabled:   true,
		Where:     routes.Where(),
		Table:     uint32(table.ID),
		Protocol:  table.Proto,
		Metric:    table.Metric,
		VRF:       table.Name(),
		PassAt:    stats.At,
		Installed: stats.Installed,
		Skipped:   stats.Skipped,
		Added:     stats.Added,
		Removed:   stats.Removed,
		Err:       stats.Err,
	}
}

// egressStatus is the egress capability as the control surface reports it. The
// configured half comes from the translator rather than from the config file,
// so a block that never became a translator reports as off rather than
// describing rules nobody installed.
func egressStatus(translator *egress.Translator) control.EgressStatus {
	cfg, stats := translator.Capability(), translator.Stats()
	advertise := make([]netip.Prefix, 0, len(cfg.Advertise))
	for _, entry := range cfg.Advertise {
		advertise = append(advertise, entry.Prefix)
	}
	return control.EgressStatus{
		Enabled:   true,
		Where:     translator.Where(),
		Source4:   cfg.Source4.String(),
		Source6:   cfg.Source6.String(),
		Return:    cfg.Return,
		Advertise: advertise,
		Announced: stats.Announced,
		PassAt:    stats.At,
		Installed: stats.Installed,
		Flows:     stats.Flows,
		Bytes:     stats.Bytes,
		Conflicts: stats.Conflicts,
		Err:       stats.Err,
	}
}
