package mrp

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	pb "github.com/jkiddo/go-atv/internal/mrpwire"
	"google.golang.org/protobuf/proto"
)

// Monitor subscribes to playback updates on a decrypted AirPlay data channel.
// Most callers should use airplay.Client.WatchNowPlaying, which sets up the
// authenticated transport. Monitor owns conn and closes it before returning.
// The handler runs synchronously, must return promptly, and may cancel ctx.
// An initial snapshot is delivered after subscription, then changed snapshots.
func Monitor(ctx context.Context, conn net.Conn, name, identifier string, handler func(State)) error {
	if handler == nil {
		conn.Close()
		return fmt.Errorf("mrp: nil state handler")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	channel := pb.NewChannel(conn)
	type received struct {
		messages []*pb.ProtocolMessage
		err      error
	}
	incoming := make(chan received, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			messages, err := channel.Receive()
			select {
			case incoming <- received{messages, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); conn.Close(); <-readerDone }()
	state := newTracker()
	receive := func() (received, error) {
		if err := ctx.Err(); err != nil {
			return received{}, err
		}
		select {
		case <-ctx.Done():
			return received{}, ctx.Err()
		case r := <-incoming:
			if r.err != nil {
				return r, r.err
			}
			return r, nil
		}
	}
	request := func(msg *pb.ProtocolMessage) error {
		id := pb.UUID()
		msg.Identifier = &id
		if err := channel.Send(msg); err != nil {
			return err
		}
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return fmt.Errorf("mrp: timed out waiting for message %d", msg.GetType())
			case r := <-incoming:
				if r.err != nil {
					return r.err
				}
				matched := false
				for _, m := range r.messages {
					state.apply(m)
					if m.GetIdentifier() == id {
						if m.GetErrorCode() != 0 {
							return fmt.Errorf("mrp: request %d failed (%d): %s", msg.GetType(), m.GetErrorCode(), m.GetErrorDescription())
						}
						matched = true
					}
				}
				if matched {
					return nil
				}
			}
		}
	}
	info := pb.NewMessage(pb.DeviceInfo)
	info.DeviceInfo = &pb.DeviceInfoMessage{
		UniqueIdentifier: proto.String(identifier), Name: proto.String(name), LocalizedModelName: proto.String("iPhone"),
		SystemBuildVersion: proto.String("20F66"), ApplicationBundleIdentifier: proto.String("com.apple.TVRemote"), ApplicationBundleVersion: proto.String("344.28"),
		ProtocolVersion: proto.Int32(1), LastSupportedMessageType: proto.Uint32(108), SupportsSystemPairing: proto.Bool(true), AllowsPairing: proto.Bool(true),
		SystemMediaApplication: proto.String("com.apple.TVMusic"), SupportsACL: proto.Bool(true), SupportsSharedQueue: proto.Bool(true), SupportsExtendedMotion: proto.Bool(true),
		SharedQueueVersion: proto.Uint32(2), DeviceClass: proto.Uint32(1), LogicalDeviceCount: proto.Uint32(1),
	}
	if err := request(info); err != nil {
		return err
	}
	connected := pb.NewMessage(pb.ConnectionState)
	connected.ConnectionState = &pb.SetConnectionStateMessage{State: proto.Uint32(2)}
	if err := channel.Send(connected); err != nil {
		return err
	}
	updates := pb.NewMessage(pb.ClientUpdates)
	updates.ClientUpdatesConfig = &pb.ClientUpdatesConfigMessage{ArtworkUpdates: proto.Bool(false), NowPlayingUpdates: proto.Bool(true), VolumeUpdates: proto.Bool(false), KeyboardUpdates: proto.Bool(false), OutputDeviceUpdates: proto.Bool(false)}
	if err := request(updates); err != nil {
		return err
	}
	// Follow pyatv's final initialization request. State can still arrive later;
	// until then the snapshot explicitly reports unknown.
	if err := request(pb.NewMessage(pb.KeyboardSession)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	previous := state.snapshot()
	handler(state.snapshot())
	for {
		r, err := receive()
		if err != nil {
			return err
		}
		for _, msg := range r.messages {
			state.apply(msg)
		}
		current := state.snapshot()
		if !reflect.DeepEqual(previous, current) {
			previous = current
			handler(state.snapshot())
		}
	}
}
