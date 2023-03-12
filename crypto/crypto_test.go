// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMAC(t *testing.T) {
	key := make([]byte, 32)
	RandBytes(key)
	msg := make([]byte, 100)
	RandBytes(msg)
	macced := AppendMAC(key, msg)
	assert.True(t, VerifyMAC(key, macced[:100], macced[100:]))
}
