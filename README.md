# go-atv

[![CI](https://github.com/jkiddo/go-atv/actions/workflows/ci.yml/badge.svg)](https://github.com/jkiddo/go-atv/actions/workflows/ci.yml)

A Go library and CLI for pairing with and controlling an Apple TV over
Apple's **Companion Link** protocol. The protocol implementation is a port
of the relevant parts of [pyatv](https://github.com/postlund/pyatv).

## What it does

- **Discovery** — finds Apple TVs via mDNS (`_companion-link._tcp`).
- **Pairing** — HAP pair-setup (SRP-6a, 3072-bit group, SHA-512) with the PIN
  shown on the TV. Credentials are stored in pyatv's format, so they are
  interchangeable with pyatv's `atvremote --credentials`.
- **Encrypted sessions** — HAP pair-verify (x25519 + Ed25519) and
  ChaCha20-Poly1305 frame encryption.
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

- **Frontmost/current app tracking.** The Companion protocol does not expose
  the currently running app; that requires the Media Remote Protocol (MRP)
  tunneled over AirPlay on tvOS 15+, which is out of scope for this port.
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

## Package layout

| Package     | Contents |
|-------------|----------|
| `opack`     | OPACK serialization (port of pyatv `support/opack.py`) |
| `tlv8`      | HAP TLV8 encoding |
| `hap`       | SRP-6a client, HKDF, ChaCha20-Poly1305 layer, HAP session framing, credentials |
| `companion` | Frames, encrypted session, pair-setup/verify, client, discovery |
| `airplay`   | AirPlay streaming: HTTP/RTSP connection, pair-setup/verify (HAP + transient), event channel, timing server, player (port of pyatv `play_url`) |
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
path can be exercised. It does not implement interactive PIN setup, AirPlay 2
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
