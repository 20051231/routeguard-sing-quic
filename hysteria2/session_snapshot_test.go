package hysteria2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func pendingForTest() *clientOffer {
	return &clientOffer{done: make(chan struct{}), cancel: func(error) {}}
}

func TestPublishedSessionIdentity(t *testing.T) {
	client := &Client{}
	first := pendingForTest()
	client.pending = first
	connection := &clientQUICConnection{}
	client.finishOffer(first, connection, nil)
	if connection.sessionID != 1 || connection.authenticatedAt.IsZero() {
		t.Fatal("published authentication did not receive an identity")
	}
	snapshot := client.SessionSnapshot()
	if snapshot.ID != 1 || snapshot.Active || snapshot.Connecting {
		t.Fatal("an absent QUIC context must not report a live session")
	}
	second := pendingForTest()
	client.pending = second
	client.finishOffer(second, &clientQUICConnection{}, nil)
	if client.SessionSnapshot().ID != 2 {
		t.Fatal("session identifier was reused in one client lifetime")
	}
}

func TestDiscardedOrFailedAuthenticationNeverPublishes(t *testing.T) {
	client := &Client{}
	pending := pendingForTest()
	pending.discarded = true
	pending.cause = context.Canceled
	client.pending = pending
	client.finishOffer(pending, nil, nil)
	if client.nextSessionID != 0 || client.conn != nil || !errors.Is(pending.err, context.Canceled) {
		t.Fatal("discarded authentication changed published state")
	}
	failed := pendingForTest()
	client.pending = failed
	client.finishOffer(failed, nil, errors.New("test failure"))
	if client.nextSessionID != 0 || client.SessionSnapshot().Active {
		t.Fatal("failed authentication was reported as warm")
	}
}

func TestCancelledWarmCallersKeepSharedPendingAuthentication(t *testing.T) {
	client := &Client{}
	pending := pendingForTest()
	client.pending = pending
	var wait sync.WaitGroup
	results := make(chan error, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 2 {
		wait.Add(1)
		go func() { defer wait.Done(); results <- client.Warm(ctx) }()
	}
	wait.Wait()
	close(results)
	for result := range results {
		if !errors.Is(result, context.Canceled) {
			t.Fatal("a caller did not observe the shared authentication result")
		}
	}
	if client.pending != pending || client.nextSessionID != 0 {
		t.Fatal("timed-out warm callers replaced the shared authentication")
	}
	client.finishOffer(pending, &clientQUICConnection{}, nil)
	if client.SessionSnapshot().ID != 1 {
		t.Fatal("one shared authentication must publish exactly one session")
	}
}

type testCloser struct{ closed atomic.Int32 }

func (c *testCloser) Close() error { c.closed.Add(1); return nil }

func TestLateSuccessfulAuthenticationIsDiscardedAfterClose(t *testing.T) {
	client := &Client{}
	pending := pendingForTest()
	client.pending = pending
	client.CloseWithError(context.Canceled)
	raw := &testCloser{}
	late := &clientQUICConnection{rawConn: raw, connDone: make(chan struct{})}
	client.finishOffer(pending, late, nil)
	if client.nextSessionID != 0 || client.conn != nil || raw.closed.Load() != 1 {
		t.Fatal("late authentication was published or not disposed")
	}
	select {
	case <-late.connDone:
	default:
		t.Fatal("discarded connection remains open")
	}
	retry := pendingForTest()
	client.pending = retry
	client.finishOffer(retry, &clientQUICConnection{}, nil)
	if client.SessionSnapshot().ID != 1 {
		t.Fatal("discarded result consumed a published identity")
	}
}
