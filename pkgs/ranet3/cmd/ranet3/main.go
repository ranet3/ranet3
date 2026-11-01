// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Command ranet3 connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel speaker. Babel exchanges control
// packets inside ESP. Address and route configuration are external unless the
// file carries a cap.table block, which turns the route reconciler on.
//
// `ranet3 daemon` is the node. Every other subcommand reads a running
// one's control socket. See cli.go.
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
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
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
	stateDir           string
	contentionProfiles bool
	level              slog.Level
}

// daemonCommand is the node itself. Its flags are its own rather than the
// root's: a reader's --control names a socket to read and this one names a
// socket to bind, and the two would share a description that fits neither.
//
// run starts the node from the options the flags came to, runDaemon unless a test reads them instead
func daemonCommand(run func(options) int) *cobra.Command {
	var o options
	var logLevel string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the ranet3 node",
		Long: `The node connects to its peers with IKEv2 and ESP, runs a Babel speaker
over those sessions, and writes the routes it learns into a kernel
routing table when the config file asks for it. The config file is TOML,
YAML or JSON, told apart by its extension: .toml, .yaml, .yml or .json.
Most other commands reach the node through its control socket.

The --state-dir flag names the directory for what outlives the process:
the flag ranet3 down leaves until ranet3 up, and the Babel router id and
seqno limit a restart starts from. A node that starts with the flag
there stays off the mesh. The daemon makes the directory with mode 0700
when it is missing.

Whoever can open the control socket runs every command, the debug
commands included.

The --pprof flag serves pprof on an address such as 127.0.0.1:6060. A CPU
profile is at /debug/pprof/profile, and this opens one as a flamegraph:

go tool pprof -http=:8081 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'

The --contention-profiles flag adds mutex and blocking profiles while
pprof is served, at a high cost in overhead.

The daemon builds everything it can refuse before it runs any of it: the
config, the pprof, metrics and control listeners, the tun, the state
directory, the antispoof filter, the exit and the route reconciler. The
tun, the node's sockets, the network watch and the parts' monitors start
their own workers as they are built, and the antispoof filter writes its
table, but nothing dials or serves before the build ends. A refusal, or
SIGINT or SIGTERM before the build ends, undoes what was built and starts
nothing: the antispoof filter's table goes where the start made it, and
stays where an earlier instance left it, as the kill switch's does. The
egress translator's stay in the families the file translates, since
building the exit removes one in a family the file no longer translates.
SIGHUP, SIGINT, SIGTERM and SIGUSR1 are taken from the start on, a second
SIGINT or SIGTERM exits at once, and a SIGHUP or SIGUSR1 that comes before
the node dials is acted on once it does.`,
		Args: noArguments,
		RunE: func(*cobra.Command, []string) error {
			if err := o.level.UnmarshalText([]byte(logLevel)); err != nil {
				return fmt.Errorf("invalid --log-level %q: log level is one of %s", logLevel, strings.Join(logLevelNames(), ", "))
			}
			if o.stateDir == "" {
				return errors.New(`invalid --state-dir "": ranet3 down needs a directory to keep its flag in`)
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
	f.StringVar(&o.stateDir, "state-dir", defaultStateDir, "Directory for state that outlives the process")
	f.StringVar(&logLevel, "log-level", defaultLogLevel, "Minimum log level")
	cmd.MarkFlagDirname("state-dir")
	cmd.RegisterFlagCompletionFunc("log-level", cobra.FixedCompletions(logLevelNames(), cobra.ShellCompDirectiveNoFileComp))
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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.level})))
	return startDaemon(opts, production)
}

// stages holds the constructor of each part of the daemon that can refuse,
// and the exit a second stop signal forces, each of which a test replaces
type stages struct {
	load   func(path string) (*config.Config, error)
	node   func(*config.Config, *events.Bus) (*client.Client, error)
	border func(*egress.Border, egress.BorderRuntime) (*kernelexit.BorderFilter, error)
	exit   func(*config.Config, *client.Client, *events.Bus) (egress.Exit, error)
	kernel func(kernel.Table, kernel.Runtime, kernel.RouteSource) (*kernel.Reconciler, error)
	force  func()
}

var production = stages{
	load: config.Load, node: client.New, border: kernelexit.NewBorderFilter, exit: newExit, kernel: kernel.New,
	force: func() { os.Exit(1) },
}

type daemonSignals struct {
	stop, reload, dump chan os.Signal
}

// notifySignals registers every signal the daemon takes, each of which
// otherwise ends the process, or for SIGUSR1 goes unread
func notifySignals() daemonSignals {
	s := daemonSignals{stop: make(chan os.Signal, 2), reload: make(chan os.Signal, 1), dump: make(chan os.Signal, 1)}
	// one registration and one reader for the stop, so a burst of two signals
	// is held by the buffer: the first stops and the second forces the exit
	signal.Notify(s.stop, os.Interrupt, syscall.SIGTERM)
	// SIGHUP reconciles rather than restarts. The registry is rewritten every
	// time any node joins the mesh, and a restart to pick that up would drop
	// every SA this node is carrying.
	signal.Notify(s.reload, syscall.SIGHUP)
	// SIGUSR1 dumps the current mesh route table to the log, the fastest way
	// to see what babel has actually installed without wiring up a separate
	// debug endpoint.
	signal.Notify(s.dump, syscall.SIGUSR1)
	return s
}

func (s daemonSignals) close() {
	signal.Stop(s.stop)
	signal.Stop(s.reload)
	signal.Stop(s.dump)
}

// startDaemon builds the daemon from s and runs it, and answers the process
// status. Its signals are registered before anything is built, and the stop
// signals are read from then on, the first closing asked and the second
// forcing the exit, through the build and its undo too.
func startDaemon(opts options, s stages) int {
	signals := notifySignals()
	defer signals.close()
	returned, asked := make(chan struct{}), make(chan struct{})
	defer close(returned)
	go watchSignals(returned, signals.stop, func() { close(asked) }, s.force)
	d, err := assemble(opts, s)
	if err != nil {
		return refuseToStart(err)
	}
	select {
	case <-asked:
		log.Print("stopping while the start builds, so it undoes what it built")
		if d.close() {
			return 1
		}
		return 0
	default:
	}
	return d.run(asked, signals)
}

// daemon holds the parts a start built, each nil where the flags or the file
// ask for none
type daemon struct {
	opts                    options
	cfg                     *config.Config
	bus                     *events.Bus
	node                    *client.Client
	pprof, metrics, control net.Listener
	border                  *kernelexit.BorderFilter
	exit                    egress.Exit
	routes                  *kernel.Reconciler
}

// assemble builds every part of the daemon that can refuse and hands the node
// the antispoof filter, the exit and the reconciler. It runs none of them, but
// the constructors start the workers of their own, the tun's, the hub's, the
// network watch and the parts' monitors, and the antispoof filter's first pass
// writes its table. A refusal closes what was built, which stops and waits
// for each of those workers. Nothing dials or serves before it returns.
func assemble(opts options, s stages) (*daemon, error) {
	d := &daemon{opts: opts}
	if err := d.build(s); err != nil {
		d.close()
		return nil, err
	}
	if d.border != nil {
		d.node.SetBorder(d.border)
	}
	if d.exit != nil {
		d.node.SetExit(d.exit)
	}
	if d.routes != nil {
		d.node.SetReconciler(client.ReconcilerOf(d.routes))
	}
	return d, nil
}

// build makes each part of d in turn and stops at the first refusal
func (d *daemon) build(s stages) (err error) {
	if d.cfg, err = s.load(d.opts.configPath); err != nil {
		return err
	}
	// an address an operator named that cannot be bound refuses the start
	if d.opts.pprofAddr != "" {
		if d.pprof, err = net.Listen("tcp", d.opts.pprofAddr); err != nil {
			return fmt.Errorf("pprof: %w", err)
		}
	}
	if d.opts.metricsAddr != "" {
		if d.metrics, err = net.Listen("tcp", d.opts.metricsAddr); err != nil {
			return fmt.Errorf("metrics: %w", err)
		}
	}
	if d.control, err = bindControl(d.opts.controlPath); err != nil {
		return err
	}
	d.bus = events.New()
	if d.node, err = s.node(d.cfg, d.bus); err != nil {
		return err
	}
	// The reload verb re-reads the file this daemon was started with, so the
	// socket and SIGHUP ask for the same thing rather than the socket guessing
	// at a default path.
	d.node.SetConfigPath(d.opts.configPath)
	// read before either switch is handed over, so neither sees a node starting down as up
	if err = d.node.SetStateDir(d.opts.stateDir); err != nil {
		return err
	}
	// The table inet ranet3 is on before the reconciler routes anything into
	// the tun, and goes only once the reconciler has withdrawn those routes and
	// the mesh has closed, so nothing forwards into the mesh while it is gone.
	// down leaves it running, since the kernel still forwards and the host's
	// services still trust mesh sources. A platform with no backend for it
	// builds no filter.
	if d.border, err = s.border(d.cfg.Border(), d.node.BorderRuntime()); err != nil {
		return err
	}
	// Each platform's build carries one exit, or refuses cap.egress here.
	if d.cfg.Egress() != nil {
		if d.exit, err = s.exit(d.cfg, d.node, d.bus); err != nil {
			return err
		}
	}
	// The reconciler is one capability, so a deployment that configures its
	// device externally writes no cap.table and gets none of this. The half
	// the file could not say is the node's own to answer, so the node answers
	// it (see client.KernelRuntime).
	if table := d.cfg.ReconcilerTable(); table != nil {
		if d.routes, err = s.kernel(*table, d.node.KernelRuntime(), d.node.Mesh.Routes); err != nil {
			return err
		}
	}
	return nil
}

// close undoes what build built, with none of it run: the reconciler, the
// exit and the antispoof filter close without a withdrawal, but for an
// antispoof table the first pass made, and then the node closes its tun and
// the listeners close. The antispoof filter's and the kill switch's tables an
// earlier instance left stay, and the translator's stay in the families the
// file translates, since building the exit removed one in any other. No close
// reads another part, so the order sets nothing. It reports whether a close
// failed.
func (d *daemon) close() (failed bool) {
	if d.routes != nil {
		failed = logged("kernel", d.routes.Close()) || failed
	}
	if d.exit != nil {
		failed = logged("egress", d.exit.Close()) || failed
	}
	if d.border != nil {
		failed = logged("antispoof", d.border.Close()) || failed
	}
	if d.node != nil {
		d.node.Close()
	}
	d.closeListeners()
	return failed
}

func (d *daemon) closeListeners() {
	for _, listener := range []net.Listener{d.control, d.metrics, d.pprof} {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func logged(name string, err error) bool {
	if err != nil {
		log.Printf("%s: %v", name, err)
	}
	return err != nil
}

func (d *daemon) run(asked <-chan struct{}, signals daemonSignals) int {
	// Set by anything that fails on a goroutine or after the daemon has
	// committed to a clean shutdown. It returns nonzero if any of them did.
	var failed atomic.Bool
	ctx, cancelFor := context.WithCancelCause(context.Background())
	stop := stopFor(d.node.MarkStopping, cancelFor)
	cancel := func() { stop(nil) }
	defer cancel()
	defer d.node.Close()
	mesh := d.node.Mesh
	go func() {
		select {
		case <-asked:
			cancel()
		case <-ctx.Done():
		}
	}()
	// the supervisor restarts the node on the exit status
	go cancelOnMeshFailure(ctx, mesh.Failed(), &failed, stop)

	var served sync.WaitGroup
	defer func() {
		d.closeListeners()
		served.Wait()
	}()
	serve := func(name string, listener net.Listener, on func(net.Listener) error) {
		served.Go(func() {
			if err := on(listener); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("%s: %v", name, err)
				failed.Store(true)
			}
		})
	}
	if d.pprof != nil {
		if d.opts.contentionProfiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(1)
		}
		log.Printf("pprof listening on http://%s/debug/pprof/", d.pprof.Addr())
		serve("pprof", d.pprof, func(l net.Listener) error { return http.Serve(l, nil) })
	}
	// A separate listener from pprof: a fleet node wants metrics scraped
	// without exposing a profiler, and a profiling run wants the profiler
	// without rewiring monitoring.
	if d.metrics != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", d.node.MetricsHandler())
		log.Printf("metrics listening on http://%s/metrics", d.metrics.Addr())
		serve("metrics", d.metrics, func(l net.Listener) error { return http.Serve(l, mux) })
	}

	stopBorder := func(error) {}
	if d.border != nil {
		borderCtx, cancelBorder := context.WithCancelCause(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			// the error is the withdrawal failing, which leaves the table in
			// the host's ruleset and is no clean exit
			if err := d.border.Run(borderCtx); err != nil {
				log.Printf("antispoof: %v", err)
				failed.Store(true)
			}
		}()
		stopBorder = func(cause error) {
			cancelBorder(cause)
			<-done
		}
		log.Printf("antispoof filter in %s, inside %s", d.border.Where(), strings.Join(d.border.Inside(), " "))
	}

	// the reconciler's run here and the exit's after the wait, each withdrawing what it holds once ctx ends
	var withdrawals sync.WaitGroup
	var firstPass <-chan struct{}
	if routes := d.routes; routes != nil {
		withdrawals.Go(func() {
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
		if mode := d.cfg.ReconcilerTable().Mode(); mode != nil && mode.Refuses() {
			firstPass = routes.FirstPass()
		}
	} else {
		// no reconciler runs to delete a table an earlier instance left, which holds the host's traffic whatever this file asks
		kernel.DeleteFallback()
		log.Printf("tun device %s ready with %d queues, configure its addresses and kernel routes externally",
			mesh.Name, mesh.QueueCount())
	}
	dials := awaitFirstPass(ctx, firstPass, firstPassWait)
	// The exit withdraws what it holds while the tun still exists, as the
	// reconciler withdraws its routes, so the two share the wait below.
	if exit := d.exit; exit != nil {
		withdrawals.Go(func() {
			// As with the reconciler, this error is the withdrawal failing as
			// often as the pass: a translation rule left in the host's packet
			// filter after shutdown must never be reported to an operator as a
			// clean exit.
			if err := exit.Run(ctx); err != nil {
				log.Printf("egress: %v", err)
				failed.Store(true)
			}
		})
		log.Printf("egress translating for %d prefixes in %s", len(d.cfg.Egress().Advertise), exit.Status().Where)
	}

	// The reconciler has to finish withdrawing while the TUN still exists,
	// and client.Run destroys it as soon as its own context is done. So the
	// mesh runs on a context canceled only once the reconciler has returned, but
	// the signal context still stops both, just in that order.
	meshCtx, stopMesh := context.WithCancel(context.Background())
	defer stopMesh()
	go func() {
		<-ctx.Done()
		announceStop(d.node.BeginStop, d.bus)
		withdrawals.Wait()
		stopMesh()
	}()

	if dials {
		// The control socket is served once the node may dial, so no verb
		// reaches the node before then. Reads answer until it closes.
		if d.control != nil {
			log.Printf("control socket listening on %s", d.opts.controlPath)
			serve("control", d.control, func(l net.Listener) error { return control.Serve(l, d.node) })
		}
		// a SIGHUP that came during the start is read here, once the node may dial
		go read(ctx, signals.reload, func() {
			if err := d.node.ReloadFrom(d.opts.configPath); err != nil {
				log.Printf("reload: %v", err)
			}
		})
		// Route installs and retractions and neighbor up and down transitions
		// are also logged as they happen.
		go read(ctx, signals.dump, func() {
			routes := mesh.Routes.Debug()
			if len(routes) == 0 {
				log.Printf("routes: (none installed)")
				return
			}
			log.Printf("routes:")
			for _, r := range routes {
				log.Printf("  %s", r)
			}
		})
		d.bus.Emit("daemon.started", "", slog.String("version", version.String()), slog.String("config", d.opts.configPath))
		// Run dials nothing where the stop began since the wait ended
		d.node.Run(meshCtx)
	}
	// Whichever side stopped first, stop the other, then let the reconciler
	// finish withdrawing before the process exits.
	stopInOrder(cancel, withdrawals.Wait, func() { stopBorder(context.Cause(ctx)) })
	if failed.Load() {
		return 1
	}
	return 0
}

// awaitFirstPass reports whether the start goes on to dial. firstPass is nil
// where the capability asks for no wait, and the pass writes the kill
// switch's table where it does not fail.
func awaitFirstPass(ctx context.Context, firstPass <-chan struct{}, wait time.Duration) bool {
	if firstPass != nil {
		select {
		case <-firstPass:
		case <-ctx.Done():
		case <-time.After(wait):
			slog.Warn("kernel's first pass has not ended, so sessions are dialed before the fallback table is written", "waited", wait)
		}
	}
	return ctx.Err() == nil
}

func read(ctx context.Context, signals <-chan os.Signal, act func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			act()
		}
	}
}

// stopInOrder ends a daemon whose mesh has stopped: it cancels the reconciler
// and the translator, waits for both to withdraw, and only then stops the
// antispoof filter, so no route into the tun outlives it. The filter
// withdraws its table then, and leaves it where the stop is for the mesh's
// failure.
func stopInOrder(cancel context.CancelFunc, wait, stopBorder func()) {
	cancel()
	wait()
	stopBorder()
}

// stopFor ends the run's context for a cause once refuse has set the node
// refusing up, reload and redial, so none starts as the stop withdraws
func stopFor(refuse func(), cancel context.CancelCauseFunc) context.CancelCauseFunc {
	return func(cause error) {
		refuse()
		cancel(cause)
	}
}

// announceStop has the node refuse up, reload and redial and wait out the
// one running before daemon.stopping tells the stream, so a caller that reads
// it meets the refusal. The subscriptions end as the stop starts rather than
// at exit, so every stream writes its closing line while the process still has
// seconds to run.
func announceStop(beginStop func(), bus *events.Bus) {
	beginStop()
	bus.Emit("daemon.stopping", "")
	bus.Close()
}

// bindControl binds the socket path names, so a path an operator named and
// this node cannot bind refuses the startup instead of leaving a node nobody
// has a way to ask anything. The default path is the one case that warns and
// carries on: it is on without being asked for, so a node whose unit cannot
// reach /var/run would otherwise stop starting on upgrade over a diagnostic it
// never requested. --control "" is the opt-out.
// a nil listener and no error is a node running without a socket
func bindControl(path string) (net.Listener, error) {
	if path == "" {
		return nil, nil
	}
	listener, err := control.Listen(path)
	switch {
	case err != nil && path == control.DefaultSocket:
		slog.Warn("running without a control socket, so the subcommands have nothing to read", "err", err)
		return nil, nil
	case err != nil:
		return nil, err
	}
	return listener, nil
}

// watchSignals starts the shutdown on the first signal and gives up on the
// second, until done is closed as the start returns. Both come off one channel
// in order, which keeps a signal from reaching nobody. See notifySignals.
func watchSignals(done <-chan struct{}, signals <-chan os.Signal, cancel context.CancelFunc, force func()) {
	select {
	case <-signals:
	case <-done:
		return
	}
	cancel()
	select {
	case <-signals:
	case <-done:
		return
	}
	log.Print("second signal, exiting without finishing shutdown")
	force()
}

// cancelOnMeshFailure keeps the cause of a cancel before the mesh's failure, since a context's first cancel wins
func cancelOnMeshFailure(ctx context.Context, meshFailed <-chan struct{}, failed *atomic.Bool, cancel context.CancelCauseFunc) {
	select {
	case <-meshFailed:
		failed.Store(true)
		cancel(kernel.ErrMeshFailed)
	case <-ctx.Done():
	}
}
