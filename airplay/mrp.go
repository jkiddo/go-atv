package airplay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jkiddo/go-atv/internal/hapconn"
	"github.com/jkiddo/go-atv/mrp"
)

// WatchNowPlaying observes system now-playing metadata over MRP tunneled through
// AirPlay 2 (tvOS 15+). It uses the credentials saved by pair-airplay and does
// not start or stop media. The callback receives an initial snapshot, followed
// by changes, until cancellation or connection loss. It must return promptly.
// Call again to reconnect after an error; stale state is never reused.
func (c *Client) WatchNowPlaying(ctx context.Context, handler func(mrp.State)) error {
	if handler == nil {
		return fmt.Errorf("airplay: nil now-playing handler")
	}
	credentials, err := c.loadCredentials()
	if err != nil {
		return err
	}
	if credentials == nil {
		return errNotPaired
	}
	if !credentials.IsHAP() {
		return fmt.Errorf("airplay: MRP requires AirPlay 2 HAP credentials; run pair-airplay on a supported device")
	}
	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return err
	}
	defer conn.close()
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(sessionCtx, conn.close)
	defer stop()
	v, err := verifyConnection(sessionCtx, conn, credentials)
	if err != nil {
		return err
	}
	rtsp := newRTSPSession(conn)
	resp, err := rtsp.setup(sessionCtx, map[string]any{
		"isRemoteControlOnly": true, "timingProtocol": "None", "sourceVersion": "550.10",
		"osName": "iPhone OS", "osVersion": "16.5", "osBuildVersion": "20F66", "model": "iPhone14,3",
		"deviceID": "AA:BB:CC:DD:EE:FF", "macAddress": "AA:BB:CC:DD:EE:FF", "sessionUUID": newUUID(), "name": c.name,
	})
	if err != nil {
		return err
	}
	body, err := unpackPlist(resp.Body)
	if err != nil {
		return err
	}
	port, ok := plistInt(body["eventPort"])
	if !ok || port < 1 || port > 65535 {
		return fmt.Errorf("airplay: invalid MRP event port")
	}
	events, err := connectEventChannel(sessionCtx, conn.remoteIP, port, v)
	if err != nil {
		return err
	}
	defer events.close()
	if err := rtsp.record(sessionCtx); err != nil {
		return err
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	seed := binary.BigEndian.Uint64(entropy[:])
	resp, err = rtsp.setup(sessionCtx, map[string]any{"streams": []any{map[string]any{
		"controlType": 2, "channelID": newUUID(), "seed": seed, "clientUUID": newUUID(), "type": 130,
		"wantsDedicatedSocket": true, "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1",
	}}})
	if err != nil {
		return err
	}
	body, err = unpackPlist(resp.Body)
	if err != nil {
		return err
	}
	streams, ok := body["streams"].([]any)
	if !ok || len(streams) != 1 {
		return fmt.Errorf("airplay: missing MRP data stream")
	}
	stream, ok := streams[0].(map[string]any)
	if !ok {
		return fmt.Errorf("airplay: malformed MRP data stream")
	}
	port, ok = plistInt(stream["dataPort"])
	if !ok || port < 1 || port > 65535 {
		return fmt.Errorf("airplay: invalid MRP data port")
	}
	output, input := v.encryptionKeys("DataStream-Salt"+strconv.FormatUint(seed, 10), "DataStream-Output-Encryption-Key", "DataStream-Input-Encryption-Key")
	var d net.Dialer
	tcp, err := d.DialContext(sessionCtx, "tcp", net.JoinHostPort(conn.remoteIP, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	data, err := hapconn.New(tcp, output, input)
	if err != nil {
		tcp.Close()
		return err
	}
	defer data.Close()
	// Failure of the owning RTSP session must terminate a seemingly healthy data
	// channel too. Report the original keep-alive error rather than cancellation.
	feedbackErr := make(chan error, 1)
	feedbackDone := make(chan struct{})
	go func() {
		defer close(feedbackDone)
		ticker := time.NewTicker(feedbackInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-events.done:
				feedbackErr <- fmt.Errorf("event channel closed")
				cancel()
				return
			case <-ticker.C:
				feedbackCtx, stopFeedback := context.WithTimeout(sessionCtx, defaultExchangeTimeout)
				feedbackFailure := rtsp.feedback(feedbackCtx)
				stopFeedback()
				if err := feedbackFailure; err != nil {
					feedbackErr <- err
					cancel()
					return
				}
			}
		}
	}()
	err = mrp.Monitor(sessionCtx, data, c.name, string(credentials.ClientID), handler)
	cancel()
	conn.close()
	<-feedbackDone
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case feedbackFailure := <-feedbackErr:
		return fmt.Errorf("airplay: MRP session: %w", feedbackFailure)
	default:
		return err
	}
}
