// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"net/netip"
	"sync"
)

// Host is the machine a reconciler reads and writes: the routing socket it
// sends on, the tables it reads back, the interface list it resolves names
// through, and the addresses it assigns. A nil Host is the kernel this process
// is running on, the one every deployment gets.
//
// Only the darwin backend consults one. linux has its own seam a layer down,
// the netlink connection its write tests drive, and reads this never.
type Host interface {
	// RouteSocket opens a write side of the platform's routing socket. The
	// caller closes it.
	RouteSocket() (RouteWriter, error)
	// Dump reads the whole routing table back, in the wire form the platform's
	// own parser reads. It crosses this seam encoded because deciding which of
	// those routes belong to this reconciler is the backend's own work and has
	// to stay under it.
	Dump() ([]byte, error)
	// Addresses reports every address one interface carries, whoever put it
	// there. Decoded, unlike Dump, because nothing is decided from the
	// encoding on this side.
	Addresses(index int) ([]netip.Prefix, error)
	// Links reads every interface with every address it carries, which the
	// network watch derives the host's links from
	Links() ([]HostInterface, error)
	// Lookup asks where one destination of one family goes. An exact mask asks
	// for that key alone rather than for a longest-prefix match. See
	// lookupDefault for why the difference decides the answer here.
	Lookup(destination, mask netip.Addr) (RouteAnswer, error)
	// InterfaceIndex resolves a device name, and InterfaceName the reverse.
	InterfaceIndex(name string) (int, error)
	InterfaceName(index int) (string, error)
	// Watch reports changes to the routing of one interface and of lo0, or of
	// every interface when index is zero, minus the one skip names, which then
	// reports a link's flags and addresses moving too. The caller closes it.
	Watch(index, skip int) (Watcher, error)
	// Assign puts prefix on device, or takes it off again.
	Assign(add bool, device string, prefix netip.Prefix) error
}

// ErrNoDefaultRoute is a host with no way off itself of the family asked
// about, which is an ordinary state on a laptop between two networks rather
// than a failure. A Host answers Lookup with it, and every caller above tells
// it apart from a lookup that went wrong: a family the host reaches nowhere
// costs nothing, and a lookup that failed is reported.
var ErrNoDefaultRoute = errors.New("kernel: the host has no default route")

// HostInterface is one interface of the host with every address it carries
type HostInterface struct {
	Index int
	Name  string
	// Up, PointToPoint and Loopback are the interface flags of those names
	Up, PointToPoint, Loopback bool
	Addresses                  []HostAddress
}

// HostAddress is one address an interface carries, under the length of its netmask
// Far is the address of the same family the kernel holds beside it in RTAX_BRD, the far end on a point-to-point link, invalid where it
// holds none
// Flags is a global unicast IPv6 address's ia6_flags, zero for any other address
type HostAddress struct {
	Prefix netip.Prefix
	Far    netip.Addr
	Flags  uint32
}

// RouteAnswer is the kernel's answer about one destination: the interface it
// would leave by and the next hop it points at, the address invalid where it
// leaves through a link instead, the key of the route that answered, invalid
// where the answer names none, and whether that route is a reject.
type RouteAnswer struct {
	Index   int
	Gateway netip.Addr
	Prefix  netip.Prefix
	Reject  bool
}

// RouteWriter is the write side of one routing socket, taking messages the
// caller has already encoded.
type RouteWriter interface {
	WriteRoute(raw []byte) error
	Close() error
}

// Watcher carries one coalesced wake-up per batch of changes to the routing
// it was opened over.
type Watcher interface {
	Changed() <-chan struct{}
	Close() error
}

// SharedWatcher is one watcher several readers follow, each wake reaching
// every reader on a channel of its own. On darwin the underlay's selection and
// the network watch both follow the host's watcher of every interface but the
// mesh, so the two read one routing socket and one event socket between them.
type SharedWatcher struct {
	watcher Watcher
	mu      sync.Mutex
	readers map[*sharedReader]bool
	stop    chan struct{}
	done    chan struct{}
	closing sync.Once
}

// shareWatcher takes over watcher, which the SharedWatcher closes once, on its
// own Close.
func shareWatcher(watcher Watcher) *SharedWatcher {
	s := &SharedWatcher{watcher: watcher, readers: make(map[*sharedReader]bool), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

func (s *SharedWatcher) run() {
	defer close(s.done)
	changed := s.watcher.Changed()
	for {
		select {
		case <-s.stop:
			return
		case <-changed:
		}
		s.mu.Lock()
		for reader := range s.readers {
			reader.wake()
		}
		s.mu.Unlock()
	}
}

// Reader is a Watcher that carries every wake of the shared one from now on.
// Its Close detaches it alone and leaves the shared watcher open.
func (s *SharedWatcher) Reader() Watcher {
	reader := &sharedReader{owner: s, signal: make(chan struct{}, 1)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readers[reader] = true
	return reader
}

// Close stops the wakes and closes the watcher, and a second call does
// nothing. A reader still attached stays open and is never woken again.
func (s *SharedWatcher) Close() error {
	var err error
	s.closing.Do(func() {
		close(s.stop)
		<-s.done
		err = s.watcher.Close()
	})
	return err
}

// sharedReader is one reader of a SharedWatcher.
type sharedReader struct {
	owner  *SharedWatcher
	signal chan struct{}
}

func (r *sharedReader) Changed() <-chan struct{} { return r.signal }

// wake never blocks: a reader that has not taken the last wake yet takes both
// as one.
func (r *sharedReader) wake() {
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *sharedReader) Close() error {
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	delete(r.owner.readers, r)
	return nil
}
