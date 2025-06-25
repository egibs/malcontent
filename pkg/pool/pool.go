package pool

import (
	"math"
	"sync"
)

const (
	defaultBuffer int = 4 * 1024   // 4KB
	maxBuffer     int = 128 * 1024 // 128KB
)

// BufferPool provides a pool of byte slices for use as buffers.
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a pool of byte slices.
func NewBufferPool(count int) *BufferPool {
	bp := &BufferPool{}

	bp.pool = sync.Pool{
		New: func() any {
			buffer := make([]byte, defaultBuffer)
			return &buffer
		},
	}

	for range count {
		buffer := make([]byte, defaultBuffer)
		bp.pool.Put(&buffer)
	}

	return bp
}

// Get retrieves a byte buffer with the required capacity.
func (bp *BufferPool) Get(size int64) []byte {
	if size <= 0 || uint64(size) >= math.MaxInt64 {
		size = 1
	}

	bufInterface := bp.pool.Get()

	bufPtr, ok := bufInterface.(*[]byte)
	if !ok || bufPtr == nil {
		return make([]byte, size)
	}

	if cap(*bufPtr) < int(size) {
		bp.pool.Put(bufPtr)
		return make([]byte, size)
	}

	return (*bufPtr)[:size]
}

// Put returns a byte buffer to the pool for future reuse.
func (bp *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	clear(buf)
	if cap(buf) <= maxBuffer {
		bp.pool.Put(&buf)
	}
}
