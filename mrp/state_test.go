package mrp

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"

	pb "github.com/jkiddo/go-atv/internal/mrpwire"
	"google.golang.org/protobuf/proto"
)

func TestPyatvPlaybackFixtures(t *testing.T) {
	raw, err := os.ReadFile("../internal/mrpwire/testdata/pyatv.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct{ Name, Protobuf string }
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	tracker := newTracker()
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(f.Protobuf)
			if err != nil {
				t.Fatal(err)
			}
			msg := &pb.ProtocolMessage{}
			if err := proto.Unmarshal(raw, msg); err != nil {
				t.Fatal(err)
			}
			tracker.apply(msg)
			s := tracker.snapshot()
			switch f.Name {
			case "queue_before_active_client", "select_player":
				if s.App != "" || s.PlaybackState != "unknown" {
					t.Fatalf("inactive: %+v", s)
				}
			case "remove_app":
				if s.App != "" || s.PlaybackState != "idle" {
					t.Fatalf("removed app: %+v", s)
				}
			case "select_client":
				if s.ContentURL != "https://example.test/episode2.mp4" || s.Title != "Episode two" || s.ItemID != "episode2" || s.Position == nil || *s.Position != 42 || s.EpisodeNumber == nil || *s.EpisodeNumber != 2 || s.PlaybackState != "playing" {
					t.Fatalf("initial: %+v", s)
				}
			case "partial_metadata":
				if s.Title != "" || s.SeriesName != "A series" || s.Duration == nil || *s.Duration != 1800 || s.Position == nil || *s.Position != 100 {
					t.Fatalf("merge: %+v", s)
				}
			case "pause", "background_player", "return_video":
				if s.PlaybackState != "paused" || s.App != "com.example.video" || s.SeriesName != "A series" {
					t.Fatalf("paused/background: %+v", s)
				}
			case "switch_app":
				if s.ContentURL != "" || s.Title != "A song" || s.Artist != "An artist" || s.SeriesName != "" || s.Duration != nil || s.MediaType != "audio" {
					t.Fatalf("switch: %+v", s)
				}
			case "remove_player", "unknown_message":
				if s.PlaybackState != "unknown" || s.Title != "" || s.Position != nil {
					t.Fatalf("removed: %+v", s)
				}
			}
		})
	}
}
func TestUnknownFieldsAndSnapshotIsolation(t *testing.T) {
	tracker := newTracker()
	path := &pb.PlayerPath{Client: &pb.NowPlayingClient{BundleIdentifier: proto.String("app")}, Player: &pb.NowPlayingPlayer{Identifier: proto.String("MediaRemote-DefaultPlayer")}}
	tracker.apply(&pb.ProtocolMessage{Type: proto.Uint32(pb.NowPlayingClientMessage), NowPlayingClient: &pb.ClientMessage{Client: path.Client}})
	state := &pb.SetStateMessage{PlayerPath: path, PlaybackState: proto.Uint32(2), PlaybackQueue: &pb.PlaybackQueue{ContentItems: []*pb.ContentItem{{Metadata: &pb.ContentItemMetadata{ElapsedTime: proto.Float64(0), Duration: proto.Float64(math.NaN()), SeasonNumber: proto.Int32(1)}}}}}
	tracker.apply(&pb.ProtocolMessage{Type: proto.Uint32(pb.SetState), SetState: state})
	s := tracker.snapshot()
	if s.Position == nil || *s.Position != 0 || s.Duration != nil {
		t.Fatalf("unknown/zero: %+v", s)
	}
	*s.Position = 100
	*s.SeasonNumber = 20
	if fresh := tracker.snapshot(); *fresh.Position != 0 || *fresh.SeasonNumber != 1 {
		t.Fatal("snapshot aliases tracker")
	}
	state.PlaybackQueue = &pb.PlaybackQueue{Location: proto.Int32(-1)}
	tracker.apply(&pb.ProtocolMessage{Type: proto.Uint32(pb.SetState), SetState: state})
	if s := tracker.snapshot(); s.PlaybackState != "idle" || s.Position != nil {
		t.Fatalf("empty queue: %+v", s)
	}
}
func TestPositionAt(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := State{PlaybackState: "playing", Position: proto.Float64(5), Duration: proto.Float64(10), PlaybackRate: proto.Float64(2), PositionTimestamp: &now}
	if got := s.PositionAt(now.Add(time.Second)); got == nil || *got != 7 {
		t.Fatalf("position: %v", got)
	}
	if got := s.PositionAt(now.Add(time.Hour)); *got != 10 {
		t.Fatal("duration not clamped")
	}
	s.PlaybackState = "paused"
	if got := s.PositionAt(now.Add(time.Hour)); *got != 5 {
		t.Fatal("paused position advanced")
	}
	s.Position = nil
	if s.PositionAt(now) != nil {
		t.Fatal("invented position")
	}
}
