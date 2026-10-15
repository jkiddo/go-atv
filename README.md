# go-atv

[![CI](https://github.com/jkiddo/go-atv/actions/workflows/ci.yml/badge.svg)](https://github.com/jkiddo/go-atv/actions/workflows/ci.yml)

A Go library and CLI for pairing with and controlling an Apple TV over
Apple's **Companion Link** protocol, with AirPlay playback and **MRP now-playing
tracking**. The protocol implementation is a port
of the relevant parts of [pyatv](https://github.com/postlund/pyatv).

## What it does

- **Discovery** — finds Apple TVs via mDNS (`_companion-link._tcp`).
- **Pairing** — HAP pair-setup (SRP-6a, 3072-bit group, SHA-512) with the PIN
  shown on the TV. Credentials are stored in pyatv's format, so they are
  interchangeable with pyatv's `atvremote --credentials`.
- **Encrypted sessions** — HAP pair-verify (x25519 + Ed25519) and
  ChaCha20-Poly1305 frame encryption.
- **Now-playing tracking** — MRP over an encrypted AirPlay 2 data channel
  reports the playing app, title, artist, album, series/episode metadata,
  playback state, duration and position, with pushed updates (tvOS 15+).
- **Power state tracking** — initial `FetchAttentionState` plus pushed
  `SystemStatus`/`TVSystemStatus` events (awake / asleep / screensaver), with
  change callbacks.
- **Remote control** — HID button presses (up/down/left/right/select/menu/
  home/volume/play_pause/wake/sleep/…).
- **Apps** — list launchable apps and launch by bundle id.
- **AirPlay video streaming** — play a video URL (or a local file, served
  automatically over HTTP) on the Apple TV, a port of pyatv's `play_url`.
  Both AirPlay 2 (encrypted control channel, event channel, timing server;
  tvOS 13+) and the legacy AirPlay 1 flow are supported, with HAP pairing
  or PIN-less transient pairing depending on what the receiver allows.

## What it deliberately does not do

- **Guaranteed foreground app tracking.** MRP identifies the app responsible for
  the active media session, which need not be the foreground app. Metadata
  availability depends on what that app publishes.
- **Direct legacy MRP connections.** Playback tracking currently uses the AirPlay 2
  tunnel; standalone `_mediaremotetv._tcp` pairing/transport is not implemented.
- Touch gestures, text input, media-control commands.
- **Audio (RAOP) streaming and screen mirroring.** Only video-by-URL is
  implemented; raw audio streaming and mirroring are out of scope.
- **Legacy MFi (pre-tvOS 10.2) AirPlay authentication.**

## CLI

Prebuilt binaries are available from [GitHub Releases](https://github.com/jkiddo/go-atv/releases).
Each archive contains the `goatv` executable and this README; SHA-256 hashes are
provided in `checksums.txt`. For Raspberry Pi, choose the Linux archive that
matches your installed OS and CPU:

| Archive suffix | Target |
| --- | --- |
| `linux_armv6.tar.gz` | 32-bit Linux on ARMv6 or newer |
| `linux_armv7.tar.gz` | 32-bit Linux on ARMv7 or newer |
| `linux_arm64.tar.gz` | 64-bit Linux on ARM64 |

The release also includes Linux AMD64 and macOS/Windows AMD64 and ARM64 builds.

To install from source, Go 1.25 or later is required:

```sh
go install github.com/jkiddo/go-atv/cmd/goatv@latest
```

Or build from a local checkout:

```sh
go build ./cmd/goatv

./goatv scan                          # discover Apple TVs via Companion and AirPlay
./goatv pair -name "Living Room"      # PIN appears on the TV
./goatv status -name "Living Room"    # on / off / unknown
./goatv watch -name "Living Room"     # JSON lines on state changes
./goatv button select -name "Living Room"
./goatv wake -name "Living Room"
./goatv sleep -name "Living Room"
./goatv apps -name "Living Room"
./goatv launch com.netflix.Netflix -name "Living Room"
./goatv pair-airplay -name "Living Room"   # separate pairing for AirPlay
./goatv play https://example.com/video.mp4 -name "Living Room"
./goatv play ./movie.mp4 -name "Living Room" -position 42
```

Credentials default to `~/.goatv/credentials`; override with `-credentials`.
AirPlay uses its own pairing and credentials file
(`~/.goatv/credentials-airplay`, override with `-airplay-credentials`); on
receivers that allow "Everyone" to AirPlay, `play` works without pairing via
transient pairing. Use `-host <ip>` to skip discovery.

## Library

Add the module to your project:

```sh
go get github.com/jkiddo/go-atv
```

Import the packages you need:

```go
import (
    "github.com/jkiddo/go-atv/airplay"
    "github.com/jkiddo/go-atv/companion"
)
```

The module's permanent home is `github.com/jkiddo/go-atv`. Consumers of the
former `github.com/jkiddo/goatv` module should update their imports. The CLI
remains named `goatv` and continues using `~/.goatv` for existing credentials.

Create a client, register callbacks, connect:

```go
client := companion.New("my-client", "/path/to/credentials", host,
    companion.WithPort(port)) // port from companion.Discover

client.AddIsOnUpdatedCallback(func(on bool) { ... })
client.AddIsAvailableUpdatedCallback(func(available bool) { ... })

if err := client.Connect(ctx); err != nil { ... }
client.KeepReconnecting(func() { /* credentials rejected — re-pair */ })
```

Pairing:

```go
client.StartPairing(ctx)          // PIN appears on the TV
client.FinishPairing(ctx, "1234") // writes the credentials file
```

AirPlay streaming:

```go
player := airplay.New("my-client", "/path/to/credentials-airplay", host,
    airplay.WithPort(device.Port), airplay.WithProperties(device.Properties))

player.StartPairing(ctx)          // only needed once, PIN appears on the TV
player.FinishPairing(ctx, "1234")

// Blocks until playback finishes or ctx is cancelled. Local file paths are
// served to the device over a temporary HTTP server automatically.
player.PlayURL(ctx, "https://example.com/video.mp4", 0)
```

## Now-playing tracking

Pair with AirPlay first; Companion credentials are separate:

```sh
./goatv pair-airplay -host 192.168.1.50
./goatv now-playing -host 192.168.1.50
./goatv watch-playing -host 192.168.1.50
```

`now-playing` prints one JSON snapshot after the MRP subscription handshake.
`watch-playing` streams changed snapshots as JSON lines until interrupted.
Use `-name` for discovery, `-airplay-credentials` for a custom credential file,
and `-airplay-port` for a custom port with `-host`.
These commands observe existing media; they do not start playback.

```go
client := airplay.New("My observer", credentialsPath, address,
    airplay.WithPort(7000))
err := client.WatchNowPlaying(ctx, func(state mrp.State) {
    fmt.Printf("%s: %s (%s)\n", state.AppName, state.Title, state.PlaybackState)
    if position := state.PositionAt(time.Now()); position != nil {
        fmt.Printf("position: %.1fs\n", *position)
    }
})
```

Import `github.com/jkiddo/go-atv/mrp` alongside `airplay`. The callback runs
synchronously and must return quickly; hand observations to a queue if further
processing might block. Use a separate client for concurrent playback operations.
Cancellation closes the control, event and data sockets. Connection/protocol
errors are returned; callers can reconnect with backoff by calling the method
again. Each connection starts with fresh state.

`State.Position` is the reported position, with its reference time in
`PositionTimestamp`; `PositionAt` extrapolates while playing/seeking. Numeric
pointers distinguish missing values from zero. Playback states are `unknown`,
`idle`, `playing`, `paused`, `stopped`, `interrupted`, and `seeking`. Queue changes
replace old metadata, while partial item updates preserve unmodified fields.
`State.ContentURL` exposes the asset URL when the app supplies it; many apps omit
it. `airplay.WithMediaURLHandler` reports the exact URL submitted by `PlayURL`,
including the temporary HTTP URL for a local file. Comparing those URLs can help
a controller identify its active sender; the callback alone is not proof that
playback succeeded.

For controllers such as Broadster, feed these observations into the existing
receiver watcher alongside Companion power/availability. Playing, paused, and
seeking guest media should keep the controller yielding. `unknown`, missing
metadata, and connection loss are not affirmative idle evidence. Even `idle`
describes a media session, not whether somebody is browsing the TV UI. Keep the
controller's existing ownership checks and idle-confirmation policy; an app name
alone does not identify the controller's own playback. Broadster's `airplay_mrp` build integrates these observations and uses a local
library checkout through its `pi/build-airplay-mrp.sh` helper until the API is
available in its pinned public dependency.

### MRP simulator

The modern simulator mode verifies HAP credentials and implements the encrypted
control, event and MRP data channels. It is separate from legacy/FairPlay mode and
uses generated, simulator-only credentials; interactive HAP pair-setup is not
implemented. It never fetches or decodes media.

```sh
# Terminal 1: credential output must name a file that does not already exist.
go run ./cmd/simulator -mrp -listen 127.0.0.1:17000 \
  -credentials-out /tmp/goatv-mrp-credentials -duration 2m \
  -title "Demo episode" -app com.example.video

# Terminal 2:
go run ./cmd/goatv watch-playing -host 127.0.0.1 -airplay-port 17000 \
  -airplay-credentials /tmp/goatv-mrp-credentials
```

In tests, use `simulator.Config{MRP: true}` and `Receiver.Credentials()`.
`SetNowPlaying(mrp.State)` replaces the active session and pushes updates;
`Advance`, `Finish`, and `Disconnect` exercise progress, completion and recovery.

Verification includes pyatv-generated protobuf/data-frame fixtures, fragmented
and malformed frames, HAP tamper rejection, partial metadata/app/player state,
and encrypted simulator lifecycle tests. The independent pyatv integration test
is opt-in so ordinary Go tests need no Python installation:

```sh
PYATV_PYTHON=/path/to/venv/bin/python go test -race ./simulator -run TestMRPPyatvInterop -v
```

Reference implementation: [pyatv](https://github.com/postlund/pyatv/tree/b277a4c8222ecdcbaab8a24e3e713ca44765adb4),
with its MIT notice in `internal/mrpwire/LICENSE.pyatv`. The `.proto` source and
fixture generator are checked in under `internal/mrpwire`; generated Go sources
are committed, so normal builds do not require `protoc`. Simulator and pyatv
verification do not establish compatibility with every app/tvOS release; physical
Apple TV verification remains separate.

## Package layout

| Package     | Contents |
|-------------|----------|
| `opack`     | OPACK serialization (port of pyatv `support/opack.py`) |
| `tlv8`      | HAP TLV8 encoding |
| `hap`       | SRP-6a client, HKDF, ChaCha20-Poly1305 layer, HAP session framing, credentials |
| `companion` | Frames, encrypted session, pair-setup/verify, client, discovery |
| `mrp`       | Now-playing snapshots, per-app/player state, partial metadata updates |
| `airplay`   | AirPlay streaming: HTTP/RTSP connection, pair-setup/verify (HAP + transient), event channel, timing server, player (port of pyatv `play_url`), MRP data tunnel |
| `cmd/goatv` | CLI |

## Fidelity & testing

Wire behaviour is ported from pyatv (which is proven against real devices);
the SRP client is verified bit-for-bit against a test vector generated with
`srptools`, the exact library pyatv uses. `companion` ships an end-to-end
test with an in-process fake Apple TV covering pairing (including wrong-PIN
rejection), verify, encrypted commands and pushed power-state events;
`airplay` ships a loopback test with a fake AirPlay 2 receiver covering
pair-verify, the encrypted control channel, SETUP/RECORD, the event
channel and the `/play` + `/playback-info` sequence:

```sh
go test -race ./...
```

GitHub Actions runs formatting checks, module consistency checks, `go vet`,
race-enabled tests, and builds on Linux and macOS for pushes and pull requests.
CI uses the Go version declared in `go.mod`. The LAN mDNS discovery test is
opt-in via `SIMULATOR_MDNS_IP` and is skipped in CI.

CI also builds all release archives with GoReleaser in snapshot mode, without
publishing. To publish a release after committing and pushing the code, create
and push a version tag, for example:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow reruns CI before publishing the archives and checksums to
GitHub Releases. Tags such as `v0.1.0-rc.1` create prereleases. The workflow uses
the built-in `GITHUB_TOKEN`; no additional release secret is required.

These loopback tests verify protocol logic. Physical-device behavior still needs
hardware validation; start a new device with `goatv scan` and the appropriate
authentication flow.


## Receiver simulator

The `simulator` package and `cmd/simulator` command use the same lifecycle and
playback controls as the simulator in go-chromecast. They accept real network
connections; no physical TV, media download or Internet connection is needed.

```sh
# Terminal 1: run a receiver with a clock that advances in real time.
go run ./cmd/simulator -listen 127.0.0.1:7000 -duration 30s

# Terminal 2: send a URL using the normal client.
go run ./cmd/goatv play -host 127.0.0.1 -airplay-credentials /tmp/goatv-simulator-client https://example.invalid/video.mp4
```

The command prints its address and discovery records as JSON, followed by playback
state changes. The default bind address is `127.0.0.1:0` (an ephemeral port).
Stop it with Ctrl-C. Flags shared by both commands are `-listen`, `-name`,
`-duration` and `-mdns-ip`.

Discovery is disabled by default. To let another machine discover
this receiver, bind to a reachable interface and explicitly enable mDNS:

```sh
go run ./cmd/simulator -listen 0.0.0.0:7000 -mdns-ip 192.168.1.35 -name "Broadster Test AirPlay"
```

Replace the example address with the simulator host's LAN address. This advertises
`_airplay._tcp`. Multicast must reach the scanner, and the TCP port must be
reachable. These development receivers have no production access controls.

### Use from Go tests

```go
receiver, err := simulator.New(simulator.Config{Duration: 10 * time.Second})
if err != nil {
    t.Fatal(err)
}
t.Cleanup(func() { _ = receiver.Close() })
// Connect the real client to 127.0.0.1 and receiver.Port().
// Then make assertions using receiver.Snapshot().
```

| Shared API | Behavior |
| --- | --- |
| `Addr()`, `Port()` | Discover the actual bound endpoint |
| `Snapshot()` | Copy URL, playback state, position, duration and play/loop counts |
| `Advance(duration)` | Move playback time deterministically; paused media stays paused |
| `Finish()` | End playback, including a repeating item |
| `FailNextPlay()` | Reject the next play request; normal protocol retry rules still apply |
| `Disconnect()` | Drop current control connections, preserve playback, allow reconnection |
| `Close()` | Stop discovery and close listeners/connections; safe to repeat |
| `TXTRecords()` | Inspect the records used for discovery without enabling multicast |

The package clock advances only through `Advance`; the command calls it on a
real-time ticker. Tests use random loopback ports and do not advertise on the LAN.

The standalone receiver implements legacy AirPlay video (HTTP/RTSP), including
`/info`, `/play`, `/playback-info`, rate changes, session-aware `/stop`, feedback,
and legacy pair-verify. `FailNextPlay` returns HTTP 500 once so the client's retry
path can be exercised. The default mode does not implement interactive PIN setup, AirPlay 2
or Companion; the existing encrypted AirPlay 2 and Companion loopback tests remain
in place.

For fixed-password testing, start with:

```sh
go run ./cmd/simulator -listen 127.0.0.1:7000 -password test-password -credentials-out /tmp/airplay-simulator-credentials
```

`-credentials-out` creates a new file containing simulator-only pre-paired keys;
it refuses to overwrite an existing file. Each simulator instance generates new
keys, so use a fresh file when restarting. In Go tests, save `Credentials()` with
`hap.SaveCredentials`, then use the real client's `StartPasswordPairing` and
`FinishPasswordPairing` to validate and save the password. The advertised `pw`
flag follows the configuration. Pairing-encryption and PIN coverage continues to
live in the existing `airplay` and `companion` tests.

These are protocol simulators, not video players or complete device emulators.
They record media URLs and report simulated progress; they do not validate codecs,
HTTP media access, buffering, DRM, or picture/audio output. Keep hardware tests for
those behaviors. Unsupported protocol commands are rejected explicitly.

```sh
go test -race ./...
```

To opt into the separate LAN discovery test, use this machine's actual IPv4:

```sh
SIMULATOR_MDNS_IP=192.168.1.35 go test -race ./simulator -run TestMDNSDiscovery -v
```

## Experimental native legacy video (`fp-setup2`)

`airplay.WithFairPlayControl(true)` opts `PlayURL` into fresh pair verification,
SAP, and AES-GCM control records on separate command and reverse-event sockets.
The CLI exposes the same option with `-fairplay-control`. It applies only to
legacy video receivers, defaults off, and does not fall back to plaintext on
failure. Normal pairing must still be completed for a protected receiver.

The parent RTSP SETUP/RECORD/feedback/TEARDOWN lifecycle normally remains active.
The tested AppleTV3,2 (OS build 12H1006, AirPlay 220.68) closes its parent after
accepting `/play`. Only for that exact `/server-info` identity, a parent EOF,
connection reset or broken pipe retires parent keepalives after a successful
encrypted playback-info response. Other versions, authentication/protocol errors,
timeouts, and loss of either video connection still fail the session. The
retirement emits a `fairplay-parent` / `retired` diagnostic event.

Every encrypted video socket prepares its own Digest authentication. Pair
verification and FairPlay setup do not replace the receiver's fixed password. Playback
completion, cancellation and stale-session cleanup use session-scoped stop;
reconnections negotiate fresh crypto instead of reusing a failed record stream.
Receiver signatures are checked when the advertised `pk` is supplied through
`WithProperties`. Discovery keys are not an out-of-band trust anchor.

For protocol tests use `simulator.Config{FairPlay: true}` or
`go run ./cmd/simulator -fairplay -listen 127.0.0.1:17000`. Optional `-pin 1234`
exercises legacy SRP PIN pairing. `-password test-password` enables Digest
protection; combine both flags to require both. `-hide-password-status` omits
the password advertisement while still challenging authentication. Wrong PINs,
passwords, and unknown paired controllers are rejected.

For QuickTime discovery on your LAN:

```sh
go run ./cmd/simulator -fairplay -listen 0.0.0.0:17000 \
  -mdns-ip YOUR_MAC_LAN_IP -name "Broadster FP Lab"
```

The simulator announces both AirPlay and RAOP. `-mdns-backend auto` uses native
`/usr/bin/dns-sd` on macOS in FairPlay mode and the Go responder elsewhere.
The native children are stopped when the receiver closes. `go` and `native`
explicitly select a backend; native requires macOS. No Python wrapper is needed.

The lab accepts native QuickTime command and encrypted reverse-event traffic.
It also opens a real parent TCP event port, sends a command and validates its
acknowledgement, and sends three UDP timing probes to the sender. State counters
expose replies and errors. Session validation requires pair verification, SAP,
SETUP and RECORD before playback; teardown ends the owning session. By default, dropping
the owning parent connection also ends playback. The hardware profile below
transfers playback ownership to the command socket and closes the parent after
accepting `/play`; losing the command socket still releases playback. It never fetches or decodes media.

Validated with QuickTime on macOS 27.0.1, including parent-event acknowledgement
and three timing replies. The full Go race suite covers session order, malformed
and fragmented messages, timing reply validation, visible/hidden password and
combined PIN/password authentication, fresh replay and cancellation. LAN checks
are opt-in:

```sh
go test -race ./...
SIMULATOR_MDNS_IP=YOUR_MAC_LAN_IP go test -race ./simulator -run TestFairPlayMDNSDiscovery -v
```

### AppleTV3,2 build 12H1006 regression profile

```sh
go run ./cmd/simulator -fairplay -fairplay-profile 'appletv3,2-12H1006' \
  -listen 127.0.0.1:17000 -password test-password
```

In Go use `Config{FairPlay: true, FairPlayProfile: FairPlayAppleTV32_12H1006}`.
This fixture models the AppleTV3,2 tested on 2026-10-14, with OS build 12H1006,
AirPlay 220.68 and protocol version 1.0. It does not stand in for newer Apple TVs.
`/server-info` includes those version fields; `DetachedParents` counts accepted
plays that close the bootstrap parent. All password-enabled FairPlay profiles
challenge protected encrypted requests with a separate Digest nonce per socket.

Regression tests cover per-socket password challenges, progress past the parent
feedback interval, completion, fresh replay, cancellation, and video transport
loss. Version/error boundary tests keep the parent exception narrow. The strict
lab profile remains available by omitting `-fairplay-profile`.

Physical playback of a complete 30-second clip was confirmed on this receiver.
Audio and rotating screen-code refresh remain unverified. Broadster's
`pi/tools/airplay-research` contains reproduction notes and sanitized evidence.
