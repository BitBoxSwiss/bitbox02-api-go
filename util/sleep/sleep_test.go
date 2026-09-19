// SPDX-License-Identifier: Apache-2.0

package sleep

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInhibitorNested(t *testing.T) {
	var transitions []string
	i := inhibitor{
		prevent: func() { transitions = append(transitions, "prevent") },
		allow:   func() { transitions = append(transitions, "allow") },
	}

	i.acquire() // Unlock workflow.
	i.acquire() // Long-running transport query.
	i.release() // The query finishes while passphrase entry continues.
	require.Equal(t, []string{"prevent"}, transitions)
	i.acquire() // Another query must not replace the workflow's assertion.
	i.release()
	require.Equal(t, []string{"prevent"}, transitions)
	i.release()
	require.Equal(t, []string{"prevent", "allow"}, transitions)

	// An unmatched release must not underflow and prevent later acquisitions.
	i.release()
	require.Equal(t, []string{"prevent", "allow"}, transitions)
	i.acquire()
	i.release()
	require.Equal(t, []string{"prevent", "allow", "prevent", "allow"}, transitions)
}

func TestInhibitorConcurrent(t *testing.T) {
	var transitions []string
	i := inhibitor{
		prevent: func() { transitions = append(transitions, "prevent") },
		allow:   func() { transitions = append(transitions, "allow") },
	}
	var acquired, finished sync.WaitGroup
	release := make(chan struct{})
	for range 32 {
		acquired.Add(1)
		finished.Go(func() {
			i.acquire()
			acquired.Done()
			<-release
			i.release()
		})
	}
	acquired.Wait()
	require.Equal(t, []string{"prevent"}, transitions)

	// The first caller can finish before other overlapping callers.
	i.acquire()
	close(release)
	finished.Wait()
	require.Equal(t, []string{"prevent"}, transitions)
	i.release()
	require.Equal(t, []string{"prevent", "allow"}, transitions)
}
