// Package mrp tracks now-playing metadata received through Media Remote Protocol.
package mrp

import (
	"math"
	"time"

	pb "github.com/jkiddo/go-atv/internal/mrpwire"
	"google.golang.org/protobuf/proto"
)

// State is a snapshot of the active media player, not the foreground UI app.
// Nil numeric fields mean the app did not supply a usable value. Times are seconds.
// "unknown" means no usable playback state has been received. "idle" only
// describes the media session; it does not prove the TV UI is idle or unused.
// Snapshots do not share mutable data with the tracker.
type State struct {
	PlaybackState     string     `json:"playbackState"`
	App               string     `json:"app,omitempty"`
	AppName           string     `json:"appName,omitempty"`
	PlayerID          string     `json:"playerId,omitempty"`
	ItemID            string     `json:"itemId,omitempty"`
	Title             string     `json:"title,omitempty"`
	Artist            string     `json:"artist,omitempty"`
	Album             string     `json:"album,omitempty"`
	Genre             string     `json:"genre,omitempty"`
	SeriesName        string     `json:"seriesName,omitempty"`
	SeasonNumber      *int32     `json:"seasonNumber,omitempty"`
	EpisodeNumber     *int32     `json:"episodeNumber,omitempty"`
	MediaType         string     `json:"mediaType,omitempty"`
	Duration          *float64   `json:"duration,omitempty"`
	Position          *float64   `json:"position,omitempty"`
	PlaybackRate      *float64   `json:"playbackRate,omitempty"`
	PositionTimestamp *time.Time `json:"positionTimestamp,omitempty"`
	Live              bool       `json:"live,omitempty"`
}

// PositionAt extrapolates a reported position while playing/seeking, clamping
// to the known duration. It never invents a position when none was reported.
func (s State) PositionAt(now time.Time) *float64 {
	if s.Position == nil {
		return nil
	}
	p := *s.Position
	if s.PositionTimestamp != nil && s.PlaybackRate != nil && (s.PlaybackState == "playing" || s.PlaybackState == "seeking") {
		p += math.Max(0, now.Sub(*s.PositionTimestamp).Seconds()) * *s.PlaybackRate
	}
	p = math.Max(0, p)
	if s.Duration != nil && *s.Duration >= 0 {
		p = math.Min(p, *s.Duration)
	}
	return &p
}

type player struct {
	state uint32
	queue *pb.PlaybackQueue
}
type client struct {
	name     string
	active   string
	selected bool
	players  map[string]*player
}
type tracker struct {
	activeKnown bool
	active      string
	clients     map[string]*client
}

func newTracker() *tracker { return &tracker{clients: make(map[string]*client)} }
func (t *tracker) getClient(info *pb.NowPlayingClient) *client {
	id := info.GetBundleIdentifier()
	c := t.clients[id]
	if c == nil {
		c = &client{players: make(map[string]*player)}
		t.clients[id] = c
	}
	if info.GetDisplayName() != "" {
		c.name = info.GetDisplayName()
	}
	return c
}
func (t *tracker) getPlayer(path *pb.PlayerPath) *player {
	c := t.getClient(path.GetClient())
	id := path.GetPlayer().GetIdentifier()
	p := c.players[id]
	if p == nil {
		p = &player{}
		c.players[id] = p
	}
	return p
}
func (t *tracker) apply(msg *pb.ProtocolMessage) {
	switch msg.GetType() {
	case pb.SetState:
		s := msg.GetSetState()
		if s == nil {
			return
		}
		p := t.getPlayer(s.GetPlayerPath())
		if s.PlaybackState != nil {
			p.state = s.GetPlaybackState()
		}
		if s.PlaybackQueue != nil {
			p.queue = proto.Clone(s.PlaybackQueue).(*pb.PlaybackQueue)
		}
	case pb.UpdateContentItem:
		u := msg.GetUpdateContentItem()
		if u == nil {
			return
		}
		p := t.getPlayer(u.GetPlayerPath())
		for _, updated := range u.GetContentItems() {
			for _, existing := range p.queue.GetContentItems() {
				if existing.GetIdentifier() == updated.GetIdentifier() && updated.Metadata != nil {
					if existing.Metadata == nil {
						existing.Metadata = &pb.ContentItemMetadata{}
					}
					proto.Merge(existing.Metadata, updated.Metadata)
				}
			}
		}
	case pb.NowPlayingClientMessage:
		c := msg.GetNowPlayingClient().GetClient()
		t.activeKnown = true
		t.active = c.GetBundleIdentifier()
		t.getClient(c)
	case pb.NowPlayingPlayerMessage:
		path := msg.GetNowPlayingPlayer().GetPlayerPath()
		c := t.getClient(path.GetClient())
		t.getPlayer(path)
		c.active = path.GetPlayer().GetIdentifier()
		c.selected = true
	case pb.UpdateClient:
		t.getClient(msg.GetUpdateClient().GetClient())
	case pb.RemoveClient:
		id := msg.GetRemoveClient().GetClient().GetBundleIdentifier()
		delete(t.clients, id)
		if t.active == id {
			t.active = ""
		}
	case pb.RemovePlayer:
		path := msg.GetRemovePlayer().GetPlayerPath()
		c := t.clients[path.GetClient().GetBundleIdentifier()]
		if c != nil {
			id := path.GetPlayer().GetIdentifier()
			delete(c.players, id)
			if c.active == id {
				c.active = ""
				c.selected = false
			}
		}
	}
}
func finite(v *float64) *float64 {
	if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) {
		return nil
	}
	return proto.Float64(*v)
}
func (t *tracker) snapshot() State {
	s := State{PlaybackState: "unknown"}
	if t.activeKnown && t.active == "" {
		s.PlaybackState = "idle"
	}
	c := t.clients[t.active]
	if c == nil || t.active == "" {
		return s
	}
	s.App = t.active
	s.AppName = c.name
	id := c.active
	if !c.selected {
		id = "MediaRemote-DefaultPlayer"
	}
	p := c.players[id]
	if p == nil {
		return s
	}
	s.PlayerID = id
	switch p.state {
	case 1:
		s.PlaybackState = "playing"
	case 2:
		s.PlaybackState = "paused"
	case 3:
		s.PlaybackState = "stopped"
	case 4:
		s.PlaybackState = "interrupted"
	case 5:
		s.PlaybackState = "seeking"
	}
	loc := p.queue.GetLocation()
	items := p.queue.GetContentItems()
	if loc < 0 || int(loc) >= len(items) {
		if p.state == 2 && p.queue != nil {
			s.PlaybackState = "idle"
		}
		return s
	}
	item := items[loc]
	m := item.GetMetadata()
	s.ItemID = item.GetIdentifier()
	s.Title = m.GetTitle()
	s.Artist = m.GetTrackArtistName()
	s.Album = m.GetAlbumName()
	s.Genre = m.GetGenre()
	s.SeriesName = m.GetSeriesName()
	s.Live = m.GetIsAlwaysLive()
	if m == nil {
		return s
	}
	if m.SeasonNumber != nil {
		s.SeasonNumber = proto.Int32(*m.SeasonNumber)
	}
	if m.EpisodeNumber != nil {
		s.EpisodeNumber = proto.Int32(*m.EpisodeNumber)
	}
	s.Duration = finite(m.Duration)
	s.Position = finite(m.ElapsedTime)
	if m.PlaybackRate != nil {
		v := float64(*m.PlaybackRate)
		s.PlaybackRate = finite(&v)
		if p.state == 1 && s.PlaybackRate != nil && v != 0 && v != 1 {
			s.PlaybackState = "seeking"
		}
	}
	if stamp := finite(m.ElapsedTimeTimestamp); stamp != nil && *stamp > 0 && *stamp < 1e11 {
		sec, frac := math.Modf(*stamp)
		ts := time.Unix(int64(sec)+978307200, int64(frac*1e9)).UTC()
		s.PositionTimestamp = &ts
	}
	switch m.GetMediaType() {
	case 1:
		s.MediaType = "audio"
	case 2:
		s.MediaType = "video"
	}
	return s
}
