package hysteria2

import "context"

// SessionSnapshot reports local authenticated QUIC state, not a promise that the
// remote peer is currently reachable. Pair ID with the core epoch and outbound tag.
// It deliberately contains no endpoint, password, token, IP address or error text.
type SessionSnapshot struct {
	ID                    uint64
	AuthenticatedAtMillis int64
	Active                bool
	Connecting            bool
	KeepIdle              bool
	TCPStreams            int
	UDPSessions           int
}

// Warm joins the normal coalesced authentication path without opening an
// application stream. The owning pool must keep idle sessions referenced and
// cancel its lifetime before closing the client; CloseWithError permits reuse.
func (c *Client) Warm(ctx context.Context) error {
	_, err := c.offer(ctx)
	return err
}

func (c *Client) SessionSnapshot() SessionSnapshot {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	snapshot := SessionSnapshot{Connecting: c.pending != nil, KeepIdle: !c.closeIdle.Load()}
	conn := c.conn
	if conn == nil {
		return snapshot
	}
	snapshot.ID = conn.sessionID
	snapshot.AuthenticatedAtMillis = conn.authenticatedAt.UnixMilli()
	snapshot.Active = conn.active()
	conn.access.RLock()
	snapshot.TCPStreams = conn.streams
	snapshot.UDPSessions = len(conn.udpConnMap)
	conn.access.RUnlock()
	return snapshot
}
