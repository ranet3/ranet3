// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

const maxMessageID = ^uint32(0)

var errMessageIDExhausted = errors.New("ike: Message ID space exhausted")

var errAnsweredInvalidSyntax = errors.New("ike: the peer answered INVALID_SYNTAX, which ends the IKE SA without a Delete")

type localRequest struct {
	exchange ExchangeType
	inner    []RawPayload
	context  *ikeContext
	result   chan requestResult
	dpd      bool
	teardown bool
	// lateFrom, where set, is when the peer may have dropped the state the request needs, so a send from then on may reach a peer without it
	lateFrom time.Time
}

type requestResult struct {
	inner []RawPayload
	err   error
	// late reports an answer that came after a send at or past the request's lateFrom
	late bool
}

type pendingRequest struct {
	localRequest
	context  *ikeContext
	msgID    uint32
	raw      []byte
	attempts int
	// sent counts transmissions. attempts drives the backoff and stops
	// growing at maxRetransmits, so it cannot also bound the exchange.
	sent int
	// lastSent is when the request last went out, a probe's resend among the sends
	lastSent time.Time
	deadline time.Time
}

type rekeySchedule struct {
	name        string
	sa          string
	interval    time.Duration
	run         func() error
	established func() (time.Time, bool)
	timer       *time.Timer
	deadline    time.Time
	due         bool
	failures    uint
	lastErr     error
	// forced marks a rekey the lists asked for, which runs only while they still leave out its SA
	forced bool
}

// RFC 7296 section 2.8: "When the lifetime of a Security Association expires, the Security Association MUST NOT be used."
func (r *rekeySchedule) lifetimeEnd() (time.Time, bool) {
	established, ok := r.established()
	return established.Add(r.interval), ok
}

func (r *rekeySchedule) outlived(now time.Time) bool {
	end, ok := r.lifetimeEnd()
	return ok && !now.Before(end)
}

func (s *Session) childEstablishedAt() (time.Time, bool) {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.childEstablished, s.Child.LocalSPI != 0
}

func (s *Session) ikeEstablishedAt() (time.Time, bool) { return s.currentContext().established, true }

// an IKE SA past its lifetime is one this end is closing
func (s *Session) ikeExpired(ctx *ikeContext) bool {
	return s.ikeRekeyInterval > 0 && !time.Now().Before(ctx.established.Add(s.ikeRekeyInterval))
}

type temporaryStreak struct {
	on    *ikeContext
	since time.Time
}

func (t *temporaryStreak) outlasted(on *ikeContext, err error, now time.Time) bool {
	rejected, ok := errors.AsType[*rejectedError](err)
	if !ok || rejected.notify.Type != N_TEMPORARY_FAILURE {
		return false
	}
	if t.on != on {
		*t = temporaryStreak{on: on, since: now}
		return false
	}
	return !now.Before(t.since.Add(temporaryFailureSpan))
}

type rekeyScheduleResult struct {
	schedule *rekeySchedule
	err      error
}

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

func randomRekeyJitter(max time.Duration) (time.Duration, error) {
	if max == 0 {
		return 0, nil
	}
	limit := new(big.Int).Add(big.NewInt(int64(max)), big.NewInt(1))
	v, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return 0, err
	}
	return time.Duration(v.Int64()), nil
}

func (s *Session) drawRekeyJitter() (time.Duration, error) {
	source := s.rekeyJitterSource
	if source == nil {
		source = randomRekeyJitter
	}
	jitter, err := source(s.rekeyJitter)
	if err != nil {
		return 0, fmt.Errorf("ike: generate rekey jitter: %w", err)
	}
	if jitter < 0 || jitter > s.rekeyJitter {
		return 0, fmt.Errorf("ike: invalid rekey jitter %s", jitter)
	}
	return jitter, nil
}

// a scheduled rekey counts from its SA's establishment, so the margin is the time it has before the SA's lifetime however late Run starts or settles the last one
func (s *Session) rekeyDue(interval time.Duration, established time.Time) (time.Time, error) {
	jitter, err := s.drawRekeyJitter()
	if err != nil {
		return time.Time{}, err
	}
	lead := interval - s.rekeyMargin - jitter
	if lead <= 0 {
		return time.Time{}, fmt.Errorf("ike: nonpositive rekey delay")
	}
	return established.Add(lead), nil
}

// an SA not yet made counts from now
func (s *Session) scheduledDelay(r *rekeySchedule) (time.Duration, error) {
	established, ok := r.established()
	if !ok {
		established = time.Now()
	}
	due, err := s.rekeyDue(r.interval, established)
	if err != nil {
		return 0, err
	}
	return max(time.Until(due), 0), nil
}

// rekeyRetryDelay backs off exponentially and then spreads the result over the
// upper half of that window. The spread breaks a simultaneous rekey:
// both ends of a collision fail at the same instant and reset the same
// deterministic backoff, so an unjittered retry reproduces the phase
// difference that caused the collision and collides again, forever. RFC 7296
// section 2.8.1 asks for the jitter for that reason.
func (s *Session) rekeyRetryDelay(failures uint) time.Duration {
	delay := s.rekeyRetryInitial
	for failures > 1 {
		if delay >= s.rekeyRetryMax/2 {
			delay = s.rekeyRetryMax
			break
		}
		delay *= 2
		failures--
	}
	source := s.rekeyJitterSource
	if source == nil {
		source = randomRekeyJitter
	}
	// A retry that cannot draw randomness is still better run unjittered.
	jitter, err := source(delay / 2)
	if err != nil || jitter < 0 || jitter > delay/2 {
		return delay
	}
	return delay - jitter
}

func (s *Session) newRekeySchedule(name, sa string, interval time.Duration, run func() error, established func() (time.Time, bool)) (*rekeySchedule, error) {
	if interval <= 0 {
		return nil, nil
	}
	schedule := &rekeySchedule{name: name, sa: sa, interval: interval, run: run, established: established}
	delay, err := s.scheduledDelay(schedule)
	if err != nil {
		return nil, err
	}
	schedule.timer, schedule.deadline = time.NewTimer(delay), time.Now().Add(delay)
	return schedule, nil
}

// retryOnly is a schedule with no interval, which falls due only for a rekey the lists force or to retry a rekey that failed
// an SA with no interval has no lifetime
func retryOnly(name, sa string, run func() error) *rekeySchedule {
	timer := time.NewTimer(0)
	timer.Stop()
	return &rekeySchedule{name: name, sa: sa, run: run, timer: timer,
		established: func() (time.Time, bool) { return time.Time{}, false }}
}

func (r *rekeySchedule) poll() {
	select {
	case <-r.timer.C:
		r.deadline = time.Time{}
		r.due = true
	default:
	}
}

func (r *rekeySchedule) reset(delay time.Duration) {
	r.timer.Reset(delay)
	r.deadline = time.Now().Add(delay)
	r.due = false
}

func nextDueRekey(schedules []*rekeySchedule, running *rekeySchedule) *rekeySchedule {
	if running != nil {
		return nil
	}
	for _, schedule := range schedules {
		if schedule.due {
			schedule.due = false
			return schedule
		}
	}
	return nil
}

// dpdInterval is how long a session goes without an authenticated message
// before it probes. A test that has to reach the probe overrides it, and zero
// means the default.
func (s *Session) dpdInterval() time.Duration {
	if s.dpdEvery > 0 {
		return s.dpdEvery
	}
	return defaultDPDInterval
}

func (s *Session) retransmitTimeout() time.Duration {
	if s.retransmitAfter > 0 {
		return s.retransmitAfter
	}
	return requestTimeout
}

// Run is the sole post-handshake IKE receiver. It dispatches authenticated
// peer requests and correlated local responses while also driving DPD.
func (s *Session) Run(ctx context.Context) error { return s.run(ctx, nil) }

func (s *Session) run(ctx context.Context, ending error) (err error) {
	if ending != nil {
		s.startClosing()
	}
	var rekeys sync.WaitGroup
	defer func() {
		_ = s.mux.Close() // unblock pending exchanges before joining them
		rekeys.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { _ = s.mux.Close() })
	defer stop()
	s.serving.Store(true)
	defer s.serving.Store(false)
	lastAuthenticated := time.Now()
	s.noteActive()
	if s.rekeyRetryInitial == 0 && s.rekeyRetryMax == 0 {
		s.rekeyRetryInitial = DefaultRetryFirst
		s.rekeyRetryMax = DefaultRetryMax
	}
	var pending *pendingRequest
	var ender *pendingRequest
	// RFC 7296 section 2.8: "the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
	// once a caller's Delete of the current IKE SA has gone out, the replacement's among them, no request goes out on that SA, a liveness check and the session's own Delete among them
	deleted := false
	childSchedule, err := s.newRekeySchedule("Child SA", "child", s.childRekeyInterval, s.RekeyChild, s.childEstablishedAt)
	if err != nil {
		return err
	}
	// a failed Child SA exchange is retried on this schedule's delay whichever path started it, and the rekeys the lists force run on it
	// so with no interval the schedule is kept to do those alone
	if childSchedule == nil {
		childSchedule = retryOnly("Child SA", "child", s.RekeyChild)
	}
	defer childSchedule.timer.Stop()
	ikeSchedule, err := s.newRekeySchedule("IKE SA", "ike", s.ikeRekeyInterval, s.RekeyIKE, s.ikeEstablishedAt)
	if err != nil {
		return err
	}
	// a disabled interval still runs the rekeys the lists force
	if ikeSchedule == nil {
		ikeSchedule = retryOnly("IKE SA", "ike", s.RekeyIKE)
	}
	defer ikeSchedule.timer.Stop()
	schedules := []*rekeySchedule{childSchedule, ikeSchedule}
	rekeyResult := make(chan rekeyScheduleResult, 1)
	var running *rekeySchedule
	startRekey := func(schedule *rekeySchedule) {
		running = schedule
		slog.Info("ike scheduled rekey starting", "sa", schedule.name)
		rekeys.Go(func() { rekeyResult <- rekeyScheduleResult{schedule, schedule.run()} })
	}
	// replaced carries how the Delete of an IKE SA whose PRF the lists left out came out
	// the session ends with it
	replaced := make(chan error, 1)
	replacing := false
	// the IKE SA is gone once its Delete is sent, however the session then ends
	// a peer replacing it as well sends a Delete that crosses this end's and closes the session first
	defer func() {
		if replacing && !errors.Is(err, ErrPRFUnlisted) {
			err = fmt.Errorf("%w, and the session ended before its Delete was answered: %v", ErrPRFUnlisted, err)
		}
	}()
	end := func(schedule *rekeySchedule, reason string, err error) {
		ending = err
		s.startClosing()
		slog.Warn("ike deleting the IKE SA", "sa", schedule.name, "reason", reason, "err", err)
		s.emit("ike.sa.closed", slog.String("sa", schedule.sa), slog.String("reason", reason), slog.String("err", err.Error()))
	}
	// RFC 7296 section 2.4: "In this case, an IKE endpoint SHOULD send a Delete payload indicating that it has closed the IKE SA unless the other endpoint is no longer responding."
	fail := func(err error) {
		if ending == nil {
			end(childSchedule, "local failure", err)
		}
	}
	// the time it returns is taken before the timer is reset, so the schedule's own retry never finds itself held
	settle := func(schedule *rekeySchedule, err error) (time.Time, error) {
		if ending != nil {
			return time.Time{}, nil
		}
		if err != nil {
			schedule.failures, schedule.lastErr = schedule.failures+1, err
			if s.temporary.outlasted(s.currentContext(), err, time.Now()) {
				end(schedule, "temporary failure", fmt.Errorf("ike: the peer answered TEMPORARY_FAILURE for %s: %w", temporaryFailureSpan, err))
				return time.Time{}, nil
			}
			delay := s.rekeyRetryDelay(schedule.failures)
			next := time.Now().Add(delay)
			schedule.reset(delay)
			slog.Warn("ike rekey failed, retrying", "sa", schedule.name, "err", err, "retry_in", delay)
			return next, nil
		}
		slog.Info("ike rekey completed", "sa", schedule.name)
		schedule.failures, schedule.lastErr, s.temporary = 0, nil, temporaryStreak{}
		schedule.forced = false
		if schedule.interval == 0 {
			return time.Time{}, nil
		}
		delay, err := s.scheduledDelay(schedule)
		if err != nil {
			return time.Time{}, err
		}
		schedule.reset(delay)
		return time.Time{}, nil
	}
	// a rekey that ended is checked against the lists once its outcome is settled, since a check while it ran left its SA to it
	resuiteDue := false
	// every Child SA exchange this end starts is settled on the Child SA schedule, whichever path started it
	settleChildRekeys := func() error {
		ended := s.childRetry.unsettled()
		if len(ended) == 0 {
			return nil
		}
		var next time.Time
		for _, rekeyErr := range ended {
			var err error
			if next, err = settle(childSchedule, rekeyErr); err != nil {
				return err
			}
		}
		s.childRetry.settled(len(ended), next)
		resuiteDue = true
		return nil
	}
	// a forced rekey falling due, after its delay or after a failure's backoff, runs only while the lists still leave out its SA
	// otherwise its schedule goes back to the rekey its interval gives, or to none
	startDueRekey := func() {
		if ending != nil || replacing {
			return
		}
		for schedule := nextDueRekey(schedules, running); schedule != nil; schedule = nextDueRekey(schedules, running) {
			child, ikeSA, _ := s.unlisted()
			if !schedule.forced || schedule == ikeSchedule && ikeSA != "" || schedule == childSchedule && child != "" {
				startRekey(schedule)
				return
			}
			schedule.forced, schedule.failures, schedule.lastErr = false, 0, nil
			if schedule.interval > 0 {
				delay, err := s.scheduledDelay(schedule)
				if err != nil {
					end(schedule, "local failure", err)
					return
				}
				schedule.reset(delay)
			}
		}
	}
	// RFC 7296 section 2.8.1: "To reduce the probability of this happening, the timing of rekeying requests SHOULD be jittered (delayed by a random amount of time after the need for rekeying is noticed)."
	// two ends reloading the same lists at once would otherwise rekey the SA at once and refuse each other's rekey
	// a schedule backing off from a failed rekey retries on its timer with the lists in force then
	force := func(schedule *rekeySchedule, sa, suite string) error {
		if suite == "" || schedule == running || schedule.due || schedule.forced || schedule.failures > 0 {
			return nil
		}
		delay, err := s.drawRekeyJitter()
		if err != nil {
			return err
		}
		// a forced rekey starts no later than the rekey its schedule holds, which keeps the margin before the SA's lifetime
		if !schedule.deadline.IsZero() {
			delay = min(delay, max(time.Until(schedule.deadline), 0))
		}
		schedule.forced = true
		schedule.reset(delay)
		s.emit("ike.suite.unlisted", slog.String("sa", sa), slog.String("suite", suite), slog.String("action", "rekey"))
		return nil
	}
	resuite := func() error {
		if ending != nil || replacing {
			return nil
		}
		child, ikeSA, prf := s.unlisted()
		if prf {
			// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
			// no rekey changes the PRF
			// so the IKE SA goes and a new handshake under the lists in force replaces it
			replacing = true
			s.emit("ike.suite.unlisted", slog.String("sa", "ike"), slog.String("suite", ikeSA), slog.String("action", "replace"))
			rekeys.Go(func() { replaced <- s.DeleteIKE() })
			return nil
		}
		if err := force(ikeSchedule, "ike", ikeSA); err != nil {
			return err
		}
		// RFC 7296 section 2.17: "KEYMAT = prf+(SK_d, Ni | Nr)"
		// a Child SA rekeys once the IKE SA it takes SK_d from holds listed transforms
		// or once that IKE SA's rekey failed
		if ikeSA == "" || ikeSchedule.failures > 0 {
			if err := force(childSchedule, "child", child); err != nil {
				return err
			}
		}
		startDueRekey()
		return nil
	}
	if err := resuite(); err != nil {
		return err
	}
	// RFC 7296 section 2.3: "An IKE endpoint MUST wait for a response to each of its messages before sending a subsequent message unless it has received a SET_WINDOW_SIZE Notify message from its peer informing it that the peer is prepared to maintain state for multiple outstanding messages in order to allow greater throughput."
	// section 1.4.1: "To delete an SA, an INFORMATIONAL exchange with one or more Delete payloads is sent listing the SPIs (as they would be expected in the headers of inbound packets) of the SAs to be deleted." and "Similar to ESP and AH SAs, IKE SAs are also deleted by sending an INFORMATIONAL exchange."
	// this end keeps one request outstanding whatever window the peer offers, so the Delete that closes an expired SA waits on the exchange outstanding at its lifetime
	// until then an expired IKE SA carries that exchange, its answers to the peer and its Delete, and starts nothing else
	expired := func() bool { return s.ikeExpired(s.currentContext()) }
	// while this end's rekey may run additional key exchanges, or waits for the peer's, the requests on the IKE SA are the rekey's alone
	livenessDue := func() time.Time {
		if expired() || deleted || s.quiet.Load() {
			return time.Now().Add(s.dpdInterval())
		}
		return lastAuthenticated.Add(s.dpdInterval())
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if ender != nil && pending != ender {
			s.mux.Close()
			return ending
		}
		// the sweeps and the lifetime and retirement deadlines of a pass take this one reading, so a lifetime a sweep did not reach is one the wait below is offered
		// the liveness and retry deadlines and the IKE SA's expiry read the clock themselves, where a stale reading would do no harm
		now := time.Now()
		if s.clock != nil {
			now = s.clock()
		}
		if err := s.expireChild(now); err != nil {
			fail(err)
		}
		if err := s.expireRetiredChildren(now); err != nil {
			fail(err)
		}
		if child, ok := s.overdueRetiring(now); ok {
			rekeys.Go(func() { s.deleteOverdueChild(child) })
		}
		s.expireRetainedContexts(now)
		s.expireChain(now)
		if err := settleChildRekeys(); err != nil {
			fail(err)
		}
		// a check the lists asked for is taken here as well as in the wait below, which may take a datagram that came after it first
		// so a peer's Delete crossing this end's own finds the IKE SA's replacement under way, and the session ends for a new handshake
		select {
		case <-s.rechecks:
			resuiteDue = true
		default:
		}
		if resuiteDue {
			resuiteDue = false
			if err := resuite(); err != nil {
				fail(err)
			}
		}
		select {
		case result := <-rekeyResult:
			running = nil
			// a rekey that failed as a saEnding ends the IKE SA with the teardown's Delete
			// while a replacement for a PRF the lists left out is under way, its Delete is that one
			if ended, ok := errors.AsType[*saEnding](result.err); ok {
				if ending == nil && !replacing {
					end(result.schedule, ended.reason, result.err)
				}
				continue
			}
			// a Child SA rekey that ran an exchange left its outcome for settleChildRekeys, so its result here only ends the run, and a run that started none counts as nothing
			if result.schedule != childSchedule {
				if _, err := settle(result.schedule, result.err); err != nil {
					end(result.schedule, "local failure", err)
				}
			}
			resuiteDue = true
			continue
		default:
		}
		for _, schedule := range schedules {
			schedule.poll()
			// RFC 7296 section 2.8: "If an SA has expired or is about to expire and rekeying attempts using the mechanisms described here fail, an implementation MUST close the IKE SA and any associated Child SAs and then MAY start new ones."
			// a rekey running at the lifetime may yet replace the SA, so its result decides, and with none running nothing can
			// a Child SA rekey started outside the schedule, as a proactive one is, counts as the scheduled one does
			rekeying := schedule == running || schedule == childSchedule && s.childRekeying.Load()
			spent := schedule == childSchedule && s.currentChildSpent()
			if ending == nil && !rekeying && (spent || schedule.outlived(now)) {
				reason, err := "lifetime", fmt.Errorf("ike: the %s reached its lifetime of %s before a rekey replaced it", schedule.name, schedule.interval)
				if spent {
					reason, err = "sequence space", errors.New("ike: the Child SA ran out of sequence numbers before a rekey replaced it")
				}
				if schedule.lastErr != nil {
					err = fmt.Errorf("%w: %w", err, schedule.lastErr)
				}
				end(schedule, reason, err)
			}
		}
		startDueRekey()
		if s.trafficSeen.Swap(false) {
			lastAuthenticated = time.Now()
			s.noteActive()
		}
		// a session ending once a caller's Delete of the IKE SA has gone out sends no Delete of its own, and the replacement's ends the session through replaced
		// it follows every check that can start the ending in the same pass, a lifetime among them, so an ending started there sends none either
		if ending != nil && deleted && pending == nil && !replacing {
			s.mux.Close()
			return ending
		}
		// the replacement's Delete ends the IKE SA in place of this one
		if ending != nil && running == nil && pending == nil && ender == nil && !replacing {
			started, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}},
				result: make(chan requestResult, 1), teardown: true})
			if err != nil {
				s.mux.Close()
				return fmt.Errorf("%w, and its Delete could not be sent: %v", ending, err)
			}
			pending, ender = started, started
		}
		if pending == nil {
			select {
			case req := <-s.requests:
				var err error
				switch {
				case deleted:
					err = errors.New("ike: the IKE SA's Delete was sent")
				// an expired IKE SA still carries its Delete, which while replacing is the replacement's
				case expired() && !deletesIKE(req.inner):
					err = errors.New("ike: the IKE SA is past its lifetime")
				default:
					pending, err = s.startRequest(req)
					deleted = err == nil && deletesIKE(req.inner) && pending.context == s.currentContext()
				}
				if err != nil {
					req.result <- requestResult{err: err}
					if errors.Is(err, errMessageIDExhausted) {
						s.mux.Close()
						return err
					}
				}
			default:
			}
		}

		deadline := livenessDue()
		if pending != nil {
			deadline = pending.deadline
		}
		for _, schedule := range schedules {
			if !schedule.deadline.IsZero() && schedule.deadline.Before(deadline) {
				deadline = schedule.deadline
			}
			if lifetime, ok := schedule.lifetimeEnd(); ok && now.Before(lifetime) && lifetime.Before(deadline) {
				deadline = lifetime
			}
		}
		// the sweeps at the top of the loop run only when the loop wakes, so it waits for their deadlines too
		if retire, ok := s.nextRetirement(now); ok && retire.Before(deadline) {
			deadline = retire
		}
		if expiry, ok := s.nextRetainedExpiry(); ok && expiry.Before(deadline) {
			deadline = expiry
		}
		if expiry, ok := s.nextChainExpiry(); ok && expiry.Before(deadline) {
			deadline = expiry
		}

		// everything this loop reacts to is selectable, so it sleeps until one of them happens rather than polling
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(time.Until(deadline), 0))
		// a nil channel takes no local request while an exchange is outstanding, the window of one above
		var requests <-chan *localRequest
		if pending == nil {
			requests = s.requests
		}
		select {
		case datagram := <-s.mux.IKE():
			if s.dispatch(datagram.Raw, datagram.Endpoint, &pending) {
				lastAuthenticated = time.Now()
				// an authenticated exchange proves the peer alive as ESP does, and on a link that carries nothing else it is the only proof
				s.noteActive()
			}
			if s.answeredInvalidSyntax {
				if ending != nil {
					return ending
				}
				return errAnsweredInvalidSyntax
			}
			continue
		case <-s.mux.Done():
			err := s.mux.Err()
			if pending != nil {
				pending.result <- requestResult{err: err}
			}
			if ending != nil {
				return ending
			}
			return err
		// the top of the loop takes these two, and the cases wake it for them
		// putting a value back never blocks, since each channel holds one element, this loop is its one reader and its one producer has no other value in flight
		case result := <-rekeyResult:
			rekeyResult <- result
			continue
		case req := <-requests:
			s.requests <- req
			continue
		// a Child SA rekey that ended is settled at the top of the loop, where the close rule also reads whether one still runs
		case <-s.childRekeyEnded:
			continue
		case <-s.childSpent:
			continue
		case err := <-s.childFailed:
			fail(err)
			continue
		case <-s.probes:
			// a quiet session's rekey or the peer's chain it waits on proves the path, and a liveness check beside them is a request the peer may destroy the IKE SA for
			if pending == nil && (expired() || deleted || s.quiet.Load()) {
				continue
			}
			probed, err := s.probe(pending)
			if err != nil {
				s.mux.Close()
				return err
			}
			pending = probed
			continue
		case <-s.rechecks:
			if err := resuite(); err != nil {
				fail(err)
			}
			continue
		case err := <-replaced:
			if err != nil {
				return fmt.Errorf("%w, and its Delete failed: %v", ErrPRFUnlisted, err)
			}
			return fmt.Errorf("%w, so the session deleted the IKE SA for a new handshake", ErrPRFUnlisted)
		case <-timer.C:
		}
		// an exchange whose IKE SA has gone is never answered, and while it is pending no later local request starts
		if pending != nil && s.contextRetired(pending.context) {
			pending.result <- requestResult{err: fmt.Errorf("ike: the IKE SA carrying this exchange was replaced")}
			pending = nil
			continue
		}
		if pending != nil && !time.Now().Before(pending.deadline) {
			// RFC 7296 section 2.1: "the initiator MUST retransmit a request until it either receives a corresponding response or deems the IKE SA to have failed."
			// an exchange its IKE SA carries past its lifetime has a silent peer's budget whatever traffic the peer keeps up, and then the IKE SA is deemed failed
			if pendingRetransmitsExhausted(pending, time.Since(lastAuthenticated) < s.dpdInterval() && !s.ikeExpired(pending.context)) {
				// section 2.1 goes on: "In the latter case, the initiator discards all state associated with the IKE SA and any Child SAs that were negotiated using that IKE SA."
				// section 2.8: "An IKE SA so created inherits all of the original IKE SA's Child SAs", so a retained IKE SA holds none and is deemed failed alone
				if s.removeRetainedContext(pending.context) {
					pending.result <- requestResult{err: fmt.Errorf("ike: IKE SA %d deemed failed after %d unanswered attempts", pending.context.spiI, pending.sent)}
					pending = nil
					continue
				}
				s.mux.Close()
				if pending == ender {
					return ending
				}
				return fmt.Errorf("ike: peer unresponsive after %d attempts", pending.sent)
			}
			// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
			// section 2.4: "an endpoint MUST NOT conclude that the other endpoint has failed based on any routing information (e.g., ICMP messages)"
			// so a send that fails locally ends nothing and only the attempt count above does
			s.sendPending(pending)
			continue
		}
		// ESP arrives without waking this select, so the traffic edge is read again before a probe
		// RFC 7296 section 2.4 asks for a check only "if no cryptographically protected messages have been received"
		if s.trafficSeen.Swap(false) {
			lastAuthenticated = time.Now()
			s.noteActive()
		}
		if pending == nil && !time.Now().Before(livenessDue()) {
			started, err := s.startLiveness()
			if err != nil {
				s.mux.Close()
				return err
			}
			pending = started
		}
		continue
	}
}

// startLiveness sends the empty INFORMATIONAL request of RFC 7296 section 2.4
func (s *Session) startLiveness() (*pendingRequest, error) {
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, result: make(chan requestResult, 1), dpd: true})
	if err != nil {
		return nil, fmt.Errorf("ike: start a liveness check: %w", err)
	}
	return pending, nil
}

// Probe asks Run to prove the path to the peer now, and never blocks
// probes Run has not acted on yet count as one
func (s *Session) Probe() {
	select {
	case s.probes <- struct{}{}:
	default:
	}
}

// probe starts a liveness check, or sends the outstanding request again now
// the resend leaves the request's attempts and backoff to their schedule, so probes can neither end an exchange early nor keep it alive
func (s *Session) probe(pending *pendingRequest) (*pendingRequest, error) {
	if pending == nil {
		started, err := s.startLiveness()
		if err != nil {
			return nil, err
		}
		s.emit("ike.probe", slog.String("action", "liveness check"), slog.Uint64("message_id", uint64(started.msgID)))
		return started, nil
	}
	pending.lastSent = time.Now()
	s.noteSend(s.mux.SendIKE(pending.raw))
	s.emit("ike.probe", slog.String("action", "retransmission"), slog.Uint64("message_id", uint64(pending.msgID)))
	return pending, nil
}

// request starts a serialized local exchange through Run. Future Child SA
// rekey support uses this path rather than receiving directly from the mux.
func (s *Session) request(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	return s.requestLocked(exchange, inner)
}

// requestLocked sends a local request while requestMu is held.
func (s *Session) requestLocked(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	return s.requestOnLocked(s.currentContext(), exchange, inner)
}

func (s *Session) requestOnLocked(context *ikeContext, exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	result := s.awaitLocked(&localRequest{exchange: exchange, inner: inner, context: context, result: make(chan requestResult, 1)})
	return result.inner, result.err
}

// awaitLocked hands req to Run and waits for its answer while requestMu is held
func (s *Session) awaitLocked(req *localRequest) requestResult {
	select {
	case s.requests <- req:
	case <-s.mux.Done():
		return requestResult{err: fmt.Errorf("ike: session closed")}
	}
	select {
	case result := <-req.result:
		return result
	case <-s.mux.Done():
		// Run may have supplied a specific failure immediately before closing.
		select {
		case result := <-req.result:
			return result
		default:
		}
		return requestResult{err: fmt.Errorf("ike: session closed")}
	}
}

func (s *Session) startRequest(req *localRequest) (*pendingRequest, error) {
	s.stateMu.RLock()
	context := req.context
	if context == nil {
		context = s.current
	}
	retired := context != s.current
	s.stateMu.RUnlock()
	// A peer rekey may replace the context after a local caller queues work.
	// Do not send a fresh negotiation on an SA the peer is already deleting.
	if req.exchange == CREATE_CHILD_SA && retired {
		return nil, fmt.Errorf("ike: IKE SA changed before Child SA exchange started")
	}
	context.localMIDMu.Lock()
	defer context.localMIDMu.Unlock()
	// Leave the final 32-bit value unused so incrementing the next local ID
	// can never wrap. RFC 7296 section 2.2 requires rekeying or closing first.
	if context.nextLocalMID == maxMessageID {
		return nil, errMessageIDExhausted
	}
	msgID := context.nextLocalMID
	flags := uint8(0)
	if !context.responder {
		flags = FlagInitiator
	}
	hdr := Header{SPIInitiator: context.spiI, SPIResponder: context.spiR, ExchangeType: req.exchange, Flags: flags, MessageID: msgID}
	raw, err := context.encrypt(context.localEncryptionKey(), hdr, nil, req.inner)
	if err != nil {
		return nil, err
	}
	// the request owns its Message ID even when this send fails, which spends an attempt as an unanswered one does
	pending := &pendingRequest{localRequest: *req, context: context, msgID: msgID, raw: raw}
	context.nextLocalMID++
	s.sendPending(pending)
	return pending, nil
}

// sendPending counts one attempt against the budget whether or not it goes out
func (s *Session) sendPending(pending *pendingRequest) {
	pending.sent++
	nextAttempt := min(pending.attempts+1, maxRetransmits)
	pending.lastSent = time.Now()
	pending.deadline = pending.lastSent.Add(retransmitDelay(s.retransmitTimeout(), nextAttempt))
	pending.attempts = nextAttempt
	s.noteSend(s.mux.SendIKE(pending.raw))
}

// noteSend warns at the first failed send of an outage and records when the outage starts and ends
func (s *Session) noteSend(err error) {
	if err == nil {
		if s.sendFailures > 0 {
			slog.Info("ike can send to the peer again", "peer", s.mux.Endpoint(), "failed", s.sendFailures)
			s.emit("ike.send.recovered", slog.Int("failed", s.sendFailures))
			s.sendFailures = 0
		}
		return
	}
	s.sendFailures++
	if s.sendFailures > 1 {
		slog.Debug("ike send failed again", "peer", s.mux.Endpoint(), "err", err, "failed", s.sendFailures)
		return
	}
	slog.Warn("ike cannot send to the peer", "peer", s.mux.Endpoint(), "err", err,
		"detail", "the session holds until a request's retransmission budget runs out")
	s.emit("ike.send.failed", slog.String("err", err.Error()))
}

func pendingRetransmitsExhausted(pending *pendingRequest, peerAlive bool) bool {
	// RFC 7296 section 2.1: "If the responder receives a retransmitted request for which it has already forgotten the response, it MUST ignore the request"
	// a peer that took a Delete of an IKE SA has deleted the SA and answers no resend, so every such Delete has the teardown's budget
	if deletesIKE(pending.inner) {
		return pending.sent >= teardownRetransmits
	}
	if pending.attempts < maxRetransmits {
		return false
	}
	if pending.dpd || !peerAlive {
		return true
	}
	// A peer that keeps authenticated traffic flowing gets more room, because
	// an ordinary exchange can lose out to a busy control loop for a while.
	// Not unlimited room: this exchange holds the one outstanding local
	// request IKEv2 allows, so until it ends there is no rekey, no Delete on
	// teardown and no dead peer detection, and the session reports up the
	// whole time. A peer that answers ESP and never answers IKE, which it can
	// do with RFC 4303 section 2.6 dummy packets alone, would otherwise pin it
	// until the sequence space ran out. RFC 7296 section 2.1 leaves the policy
	// open, "until it either receives a corresponding response or deems the
	// IKE SA to have failed". This is where it is deemed to have failed.
	return pending.sent >= maxRetransmitsWhileBusy
}

func retransmitDelay(first time.Duration, attempt int) time.Duration {
	if attempt <= 1 {
		return first
	}
	return first << min(attempt-1, maxRetransmits-1)
}

// dispatch returns true only when raw is a fresh authenticated message. Run
// uses that result as evidence of peer liveness. Authenticated replays may
// receive a cached response, but must not refresh DPD or migrate the endpoint.
func (s *Session) dispatch(raw []byte, source transport.Endpoint, pending **pendingRequest) bool {
	hdr, err := decodeHeader(raw)
	if err != nil || higherVersion(s.mux.SendIKETo, hdr, source) {
		return false
	}
	if hdr.MajorVersion != 2 || hdr.Length != uint32(len(raw)) {
		return false
	}
	ctx := s.contextForHeader(hdr)
	if ctx == nil {
		return false
	}
	var matching *pendingRequest
	if hdr.IsResponse() {
		matching = *pending
		if hdr.IsInitiator() != ctx.responder || matching == nil || matching.context != ctx ||
			hdr.MessageID != matching.msgID || hdr.ExchangeType != matching.exchange {
			return false
		}
	} else if hdr.IsInitiator() != ctx.responder {
		return false
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
	if err != nil {
		return false
	}
	if matching == nil {
		s.stateMu.RLock()
		nextPeerMID := ctx.nextPeerMID
		lastPeerResponseID := ctx.lastPeerResponseID
		lastPeerResponse := ctx.lastPeerResponse
		s.stateMu.RUnlock()
		if hdr.MessageID != nextPeerMID {
			if nextPeerMID > 0 && hdr.MessageID == nextPeerMID-1 && lastPeerResponseID == hdr.MessageID {
				// a replay can come from any address, so this send says nothing about the path to the peer
				_ = s.mux.SendIKETo(lastPeerResponse, source)
			}
			return false
		}
		// RFC 7296 section 2.2: "In the unlikely event that Message IDs grow too large to fit in 32 bits, the IKE SA MUST be closed or rekeyed."
		// a request at the last Message ID leaves no next one to expect, so the IKE SA closes rather than take it
		if nextPeerMID == maxMessageID {
			s.mux.Close()
			return true
		}
		// RFC 7296 section 2.23: "Also, dynamic address update should only be done in response to a new packet"
		// and: "otherwise, an attacker can revert the addresses with old replayed packets."
		if s.mux.AdoptEndpoint(source) {
			s.emit("ike.endpoint.moved", slog.String("endpoint", source.String()))
		}
	}
	inner, err := decodeMessagePlaintext(innerFirst, plaintext)
	if err != nil {
		if matching != nil {
			matching.result <- requestResult{err: fmt.Errorf("ike: malformed authenticated response: %w", err)}
			*pending = nil
		} else if response, _ := s.refuseRequest(ctx, hdr.MessageID, hdr.ExchangeType, err); response != nil {
			_ = s.mux.SendIKETo(response, source)
		}
		// section 2.21.3's "the IKE SA is deleted" names the IKE SA the request came on, so a retained one ends alone, as when the peer answers INVALID_SYNTAX on it
		if matching == nil && s.removeRetainedContext(ctx) {
			return true
		}
		// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
		// section 2.21.3 on a response with errors: "Because sending such error messages as an INFORMATIONAL exchange might lead to further errors that could cause loops, such errors SHOULD NOT be sent."
		// and: "If errors are seen that indicate that the peers do not have the same state, it might be good to delete the IKE SA to clean up state and start over."
		s.mux.Close()
		return true
	}
	if matching != nil {
		if unsupported, found := firstUnsupportedCritical(outer.Payloads, inner); found {
			matching.result <- requestResult{err: fmt.Errorf("ike: response marks unsupported payload type %d critical", unsupported)}
			*pending = nil
			return true
		}
		if _, found := findNotify(inner, N_INVALID_SYNTAX); found {
			*pending = nil
			s.endAtInvalidSyntax(ctx, matching, inner)
			return true
		}
		// RFC 7296 section 2.4: "Receipt of a fresh cryptographically protected message on an IKE SA or any of its Child SAs ensures liveness of the IKE SA and all of its Child SAs."
		// so a liveness check refused with any other error proves the peer is there and changes nothing, and the IKE SA a refused Delete ends is gone here all the same
		// nothing reads the answers to these two requests of Run's own, so a refusal is told here
		if matching.dpd || matching.teardown {
			if refused := refusal("INFORMATIONAL", inner); refused != nil && matching.dpd {
				slog.Warn("ike the peer refused a liveness check", "err", refused)
			} else if refused != nil {
				slog.Warn("ike the peer refused the Delete that ends the IKE SA", "err", refused)
			}
		}
		matching.result <- requestResult{inner: inner, late: !matching.lateFrom.IsZero() && !matching.lastSent.Before(matching.lateFrom)}
		*pending = nil
		return true
	}
	response, err := s.handleRequest(ctx, hdr, outer.Payloads, inner)
	if err != nil {
		if response != nil {
			_ = s.mux.SendIKETo(response, source)
		}
		if _, refused := errors.AsType[invalidSyntaxSent](err); refused && s.removeRetainedContext(ctx) {
			return true
		}
		s.mux.Close()
		return true
	}
	s.stateMu.Lock()
	ctx.lastPeerResponseID = hdr.MessageID
	ctx.lastPeerResponse = response
	ctx.nextPeerMID++
	s.stateMu.Unlock()
	// a failed reply keeps the session, since the peer retransmits and is answered from the reply kept above
	s.noteSend(s.mux.SendIKETo(response, source))
	return true
}

func (s *Session) contextForHeader(hdr *Header) *ikeContext {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if hdr.SPIInitiator == s.current.spiI && hdr.SPIResponder == s.current.spiR {
		return s.current
	}
	// past its lifetime a retained IKE SA answers no request, and takes only the answer to this end's own Delete on it
	for _, retained := range []*ikeContext{s.old, s.collision} {
		if retained != nil && hdr.SPIInitiator == retained.spiI && hdr.SPIResponder == retained.spiR && (hdr.IsResponse() || !s.ikeExpired(retained)) {
			return retained
		}
	}
	return nil
}

func (s *Session) handleRequest(ctx *ikeContext, hdr *Header, cleartext, inner []RawPayload) ([]byte, error) {
	if response, rejected, err := s.rejectUnsupportedCritical(ctx, hdr, cleartext, inner); rejected {
		return response, err
	}
	if hdr.ExchangeType == INFORMATIONAL {
		// RFC 7296 section 2.21.2: "In an IKE_AUTH exchange, or in the INFORMATIONAL exchange immediately following it (in case an error happened when processing a response to IKE_AUTH), the UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, and AUTHENTICATION_FAILED notifications are the only ones to cause the IKE SA to be deleted or not created, without a Delete payload."
		if ctx.answeredAuth && hdr.MessageID == ctx.authMID+1 {
			if notify, ok := authFailure(inner); ok {
				response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
				if err != nil {
					return nil, err
				}
				return response, fmt.Errorf("ike: peer ended the IKE SA with notify type %d", notify)
			}
		}
		var deletes []Delete
		for _, p := range inner {
			if p.Type != PayloadD {
				continue
			}
			d, err := DecodeDelete(p.Body)
			if err != nil {
				return s.refuseRequest(ctx, hdr.MessageID, INFORMATIONAL, err)
			}
			deletes = append(deletes, d)
			if d.Protocol == ProtoIKE {
				response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
				if err != nil {
					return nil, err
				}
				if s.removeRetainedContext(ctx) || s.adoptCollisionOnPeerDelete(ctx) {
					return response, nil
				}
				return response, fmt.Errorf("peer deleted IKE SA")
			}
		}
		var responseSPIs [][]byte
		for _, d := range deletes {
			if d.Protocol != ProtoESP {
				continue
			}
			remoteSPIs := make([]uint32, len(d.SPIs))
			for i, spi := range d.SPIs {
				remoteSPIs[i] = binary.BigEndian.Uint32(spi)
			}
			// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
			// a Child SA the dataplane refuses to close is left out of the answer, and the IKE SA's Delete that follows it closes every Child SA
			localSPIs, err := s.deleteChildren(remoteSPIs)
			if err != nil {
				s.ChildFailed(fmt.Errorf("ike: close a Child SA the peer deleted: %w", err))
			}
			for _, localSPI := range localSPIs {
				spi := make([]byte, 4)
				binary.BigEndian.PutUint32(spi, localSPI)
				responseSPIs = append(responseSPIs, spi)
			}
		}
		var responsePayloads []RawPayload
		if len(responseSPIs) > 0 {
			responsePayloads = []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: responseSPIs})}}
		}
		return s.response(ctx, hdr.MessageID, INFORMATIONAL, responsePayloads)
	}
	if hdr.ExchangeType == CREATE_CHILD_SA {
		if sa := findType(inner, PayloadSA); sa != nil {
			props, err := DecodeSA(sa.Body)
			if err == nil && len(props) > 0 && props[0].Protocol == ProtoIKE {
				return s.handleIKERekey(ctx, hdr.MessageID, inner)
			}
		}
		return s.handleChildRekey(ctx, hdr.MessageID, inner)
	}
	if hdr.ExchangeType == IKE_FOLLOWUP_KE {
		return s.handleFollowup(ctx, hdr.MessageID, inner)
	}
	return s.refuseRequest(ctx, hdr.MessageID, hdr.ExchangeType, fmt.Errorf("ike: unsupported exchange type %d", hdr.ExchangeType))
}

// refuseRequest answers a request with INVALID_SYNTAX, and the error it returns, why, ends the IKE SA
// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// section 3.10.1 on INVALID_SYNTAX: "To aid debugging, more detailed error information should be written to a console or log."
func (s *Session) refuseRequest(ctx *ikeContext, msgID uint32, exchange ExchangeType, why error) ([]byte, error) {
	response, err := s.responseNotify(ctx, msgID, exchange, N_INVALID_SYNTAX)
	if err != nil {
		return nil, err
	}
	slog.Warn("ike answered a request with INVALID_SYNTAX and ends the IKE SA", "exchange", exchange, "err", why)
	return response, invalidSyntaxSent{why}
}

// invalidSyntaxSent is why refuseRequest answered INVALID_SYNTAX, which tells dispatch to end the IKE SA the request came on
type invalidSyntaxSent struct{ error }

func (e invalidSyntaxSent) Unwrap() error { return e.error }

// endAtInvalidSyntax deletes ctx, whose peer answered this end's request with INVALID_SYNTAX, with no Delete: a retained IKE SA here, and the current one as Run returns
// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// a retained IKE SA is one this end is deleting already, and its request reads the answer as any other refusal
func (s *Session) endAtInvalidSyntax(ctx *ikeContext, request *pendingRequest, answer []RawPayload) {
	slog.Warn("ike the peer answered INVALID_SYNTAX, which ends the IKE SA without a Delete", "exchange", request.exchange, "spi", ctx.spiI)
	if s.removeRetainedContext(ctx) {
		request.result <- requestResult{inner: answer}
		return
	}
	request.result <- requestResult{err: errAnsweredInvalidSyntax}
	// an IKE SA this end is closing has its end told already
	if !s.closing.Load() {
		s.emit("ike.sa.closed", slog.String("sa", "ike"), slog.String("reason", "invalid syntax"), slog.String("err", errAnsweredInvalidSyntax.Error()))
	}
	s.answeredInvalidSyntax = true
}

func authFailure(payloads []RawPayload) (NotifyType, bool) {
	return findNotify(payloads, N_UNSUPPORTED_CRITICAL_PAYLOAD, N_INVALID_SYNTAX, N_AUTHENTICATION_FAILED)
}

// findNotify returns the type of the first notify in payloads that is one of types, passing over a notify that does not decode
func findNotify(payloads []RawPayload, types ...NotifyType) (NotifyType, bool) {
	for _, payload := range payloads {
		if payload.Type != PayloadN {
			continue
		}
		if notify, err := DecodeNotify(payload.Body); err == nil && slices.Contains(types, notify.Type) {
			return notify.Type, true
		}
	}
	return 0, false
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 3.2: "The reasoning behind not setting the critical bit for payloads defined in this document is that all implementations MUST understand all payload types defined in this document and therefore must ignore the critical bit's value."
// section 4: "If the critical bit is set in an unsupported payload header, all implementations MUST reject the messages containing those payloads."
// the types defined there run from SA to EAP, and this end skips the ones it does not act on: CERT, CERTREQ, V, CP and EAP
func supportedPayloadType(payloadType PayloadType) bool {
	return payloadType >= PayloadSA && payloadType <= PayloadEAP
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected and the response to the IKE request containing that payload MUST include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an unsupported critical payload was included. In that Notify payload, the Notification Data contains the one-octet payload type."
func (s *Session) rejectUnsupportedCritical(ctx *ikeContext, hdr *Header, cleartext, inner []RawPayload) ([]byte, bool, error) {
	unsupported, found := firstUnsupportedCritical(cleartext, inner)
	if !found {
		return nil, false, nil
	}
	response, err := s.responseNotifyData(ctx, hdr.MessageID, hdr.ExchangeType, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)})
	return response, true, err
}

func (s *Session) response(ctx *ikeContext, msgID uint32, exchange ExchangeType, inner []RawPayload) ([]byte, error) {
	flags := uint8(FlagResponse)
	if !ctx.responder {
		flags |= FlagInitiator
	}
	hdr := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, Flags: flags, MessageID: msgID}
	raw, err := ctx.encrypt(ctx.localEncryptionKey(), hdr, nil, inner)
	if err != nil {
		return nil, fmt.Errorf("ike: build response: %w", err)
	}
	return raw, nil
}

func (ctx *ikeContext) localEncryptionKey() []byte {
	if ctx.responder {
		return ctx.sker
	}
	return ctx.skei
}

func (ctx *ikeContext) peerEncryptionKey() []byte {
	if ctx.responder {
		return ctx.skei
	}
	return ctx.sker
}

func (s *Session) responseNotify(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType) ([]byte, error) {
	return s.responseNotifyData(ctx, msgID, exchange, notifyType, nil)
}

func (s *Session) responseNotifyData(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, data []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType, Data: data})}})
}

func (s *Session) responseNotifySA(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, protocol ProtocolID, spi []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: protocol, SPI: spi, Type: notifyType})}})
}

// DeleteIKE ends the IKE SA with a Delete and returns the peer's refusal of it, after which the IKE SA is gone here all the same
// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
// the caller bounds how long the exchange may take
func (s *Session) DeleteIKE() error {
	s.startClosing()
	payloads := []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}
	if s.serving.Load() {
		answer, err := s.request(INFORMATIONAL, payloads)
		if err != nil {
			return err
		}
		if err := refusal("INFORMATIONAL", answer); err != nil {
			slog.Warn("ike the peer refused the Delete that ends the IKE SA", "err", err)
			return err
		}
		return nil
	}
	// before Run serves the session nothing drains the request queue, so a Delete sent through it would never go out
	return s.sendUnansweredRequest(payloads)
}

// closingSignal is closed once the IKE SA starts to close
func (s *Session) closingSignal() chan struct{} {
	s.closedMu.Lock()
	defer s.closedMu.Unlock()
	if s.closed == nil {
		s.closed = make(chan struct{})
	}
	return s.closed
}

// startClosing marks the IKE SA closing and wakes what waits on closingSignal
func (s *Session) startClosing() {
	s.closing.Store(true)
	closed := s.closingSignal()
	s.closedMu.Lock()
	defer s.closedMu.Unlock()
	select {
	case <-closed:
	default:
		close(closed)
	}
}

// sendUnansweredRequest transmits one encrypted request and does not wait for
// the response.
func (s *Session) sendUnansweredRequest(inner []RawPayload) error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	ctx := s.currentContext()
	ctx.localMIDMu.Lock()
	defer ctx.localMIDMu.Unlock()
	flags := uint8(0)
	if !ctx.responder {
		flags = FlagInitiator
	}
	header := Header{
		SPIInitiator: ctx.spiI,
		SPIResponder: ctx.spiR,
		ExchangeType: INFORMATIONAL,
		Flags:        flags,
		MessageID:    ctx.nextLocalMID,
	}
	request, err := ctx.encrypt(ctx.localEncryptionKey(), header, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build IKE Delete: %w", err)
	}
	ctx.nextLocalMID++
	return s.mux.SendIKE(request)
}
