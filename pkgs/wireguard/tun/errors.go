package tun

import (
	"errors"
)

var (
	// ErrTooManySegments is returned by Reader.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")

	// ErrInvalidFrame is returned by Reader.Read() when the device produced a
	// frame that cannot be decoded into packets. The frame is consumed and
	// lost. This error should not cause reads to cease.
	ErrInvalidFrame = errors.New("invalid frame")
)
