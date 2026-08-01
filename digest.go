package resty

import "sync/atomic"

type DigestAuth struct {
	nonceCount uint32
}

func (d *DigestAuth) GetNextNonce() uint32 {
	return atomic.AddUint32(&d.nonceCount, 1)
}
