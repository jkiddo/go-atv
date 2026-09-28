// Package companion implements Apple's Companion Link protocol as used by
// Apple TV (tvOS). It is a focused port of pyatv's Companion support:
// pairing, encrypted sessions, HID commands, app listing/launching and
// power-state tracking via SystemStatus events.
package companion

import (
	"errors"
	"fmt"
	"io"
)

// FrameType identifies a Companion frame.
type FrameType byte

// Frame types from pyatv's connection.py.
const (
	FrameUnknown                FrameType = 0
	FrameNoOp                   FrameType = 1
	FramePSStart                FrameType = 3
	FramePSNext                 FrameType = 4
	FramePVStart                FrameType = 5
	FramePVNext                 FrameType = 6
	FrameUOpack                 FrameType = 7
	FrameEOpack                 FrameType = 8
	FramePOpack                 FrameType = 9
	FramePAReq                  FrameType = 10
	FramePARsp                  FrameType = 11
	FrameSessionStartRequest    FrameType = 16
	FrameSessionStartResponse   FrameType = 17
	FrameSessionData            FrameType = 18
	FrameFamilyIdentityRequest  FrameType = 32
	FrameFamilyIdentityResponse FrameType = 33
	FrameFamilyIdentityUpdate   FrameType = 34
)

func (f FrameType) String() string {
	names := map[FrameType]string{
		FrameNoOp: "NoOp", FramePSStart: "PS_Start", FramePSNext: "PS_Next",
		FramePVStart: "PV_Start", FramePVNext: "PV_Next", FrameUOpack: "U_OPACK",
		FrameEOpack: "E_OPACK", FramePOpack: "P_OPACK",
	}
	if name, ok := names[f]; ok {
		return name
	}
	return fmt.Sprintf("FrameType(%d)", byte(f))
}

const frameHeaderLength = 4

// maxFramePayload bounds incoming frames; the length field is 24 bits.
const maxFramePayload = 1<<24 - 1

// frameHeader builds the 4-byte header: type + 24-bit big-endian payload
// length (including the 16-byte auth tag when encrypted).
func frameHeader(frameType FrameType, payloadLength int) []byte {
	return []byte{
		byte(frameType),
		byte(payloadLength >> 16),
		byte(payloadLength >> 8),
		byte(payloadLength),
	}
}

// readFrame reads one raw (possibly encrypted) frame from r.
func readFrame(r io.Reader) (FrameType, []byte, []byte, error) {
	header := make([]byte, frameHeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > maxFramePayload {
		return 0, nil, nil, errors.New("companion: oversized frame")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, nil, err
	}
	return FrameType(header[0]), payload, header, nil
}
