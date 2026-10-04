// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"net"
)

// Caller is the process on the other end of a control connection
// the kernel reported it when the connection was accepted
type Caller struct {
	UID uint32
	// PID is zero where the platform reports none
	PID int32
}

type callerKey struct{}

// CallerOf is the caller behind a request's context
// false means the connection carried no credentials
// a listener other than a unix socket and a platform without peer credentials both arrive that way
func CallerOf(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(callerKey{}).(Caller)
	return caller, ok
}

func withCaller(ctx context.Context, caller Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

// connCaller is the server's ConnContext
// the kernel is asked once per connection, since every request on it comes from the process that connected
func connCaller(ctx context.Context, conn net.Conn) context.Context {
	if bounded, ok := conn.(*boundedConn); ok {
		conn = bounded.Conn
	}
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return ctx
	}
	caller, ok := peerCred(socket)
	if !ok {
		return ctx
	}
	return withCaller(ctx, caller)
}
