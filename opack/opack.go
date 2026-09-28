// Package opack implements the OPACK serialization format used by Apple's
// Companion protocol. It is a port of pyatv's pyatv/support/opack.py and
// intentionally mirrors its behaviour, including the object-reuse list.
package opack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
)

// UUID is a 16-byte value serialized with the 0x05 tag.
type UUID [16]byte

// Pack serializes v to OPACK bytes.
//
// Supported types: nil, bool, int variants (non-negative), uint variants,
// float64/float32, string, []byte, UUID, []any and map[string]any. Map keys
// are emitted in sorted order so output is deterministic.
func Pack(v any) ([]byte, error) {
	var objects [][]byte
	return pack(v, &objects)
}

func pack(v any, objects *[][]byte) ([]byte, error) {
	var packed []byte

	switch data := v.(type) {
	case nil:
		packed = []byte{0x04}
	case bool:
		if data {
			packed = []byte{0x01}
		} else {
			packed = []byte{0x02}
		}
	case UUID:
		packed = append([]byte{0x05}, data[:]...)
	case int:
		return pack(int64(data), objects)
	case int8:
		return pack(int64(data), objects)
	case int16:
		return pack(int64(data), objects)
	case int32:
		return pack(int64(data), objects)
	case uint:
		return pack(uint64(data), objects)
	case uint8:
		return pack(uint64(data), objects)
	case uint16:
		return pack(uint64(data), objects)
	case uint32:
		return pack(uint64(data), objects)
	case uint64:
		if data > math.MaxInt64 {
			return nil, fmt.Errorf("opack: integer too large: %d", data)
		}
		return pack(int64(data), objects)
	case int64:
		if data < 0 {
			return nil, fmt.Errorf("opack: negative integers not supported: %d", data)
		}
		packed = packInt(data)
	case float32:
		return pack(float64(data), objects)
	case float64:
		packed = make([]byte, 9)
		packed[0] = 0x36
		binary.LittleEndian.PutUint64(packed[1:], math.Float64bits(data))
	case string:
		packed = packString(data)
	case []byte:
		packed = packBytes(data)
	case []any:
		count := len(data)
		if count > 0xF {
			count = 0xF
		}
		packed = []byte{0xD0 + byte(count)}
		for _, item := range data {
			b, err := pack(item, objects)
			if err != nil {
				return nil, err
			}
			packed = append(packed, b...)
		}
		if len(data) >= 0xF {
			packed = append(packed, 0x03)
		}
	case map[string]any:
		count := len(data)
		if count > 0xF {
			count = 0xF
		}
		packed = []byte{0xE0 + byte(count)}
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			kb, err := pack(k, objects)
			if err != nil {
				return nil, err
			}
			vb, err := pack(data[k], objects)
			if err != nil {
				return nil, err
			}
			packed = append(packed, kb...)
			packed = append(packed, vb...)
		}
		if len(data) >= 0xF {
			packed = append(packed, 0x03)
		}
	default:
		return nil, fmt.Errorf("opack: unsupported type %T", v)
	}

	// Replace duplicate objects with a reference into the object list,
	// mirroring pyatv's pack implementation.
	if idx := indexOfPacked(*objects, packed); idx >= 0 {
		switch {
		case idx < 0x21:
			packed = []byte{0xA0 + byte(idx)}
		case idx <= 0xFF:
			packed = []byte{0xC1, byte(idx)}
		case idx <= 0xFFFF:
			packed = []byte{0xC2, 0, 0}
			binary.LittleEndian.PutUint16(packed[1:], uint16(idx))
		default:
			packed = []byte{0xC3, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(packed[1:], uint32(idx))
		}
	} else if len(packed) > 1 {
		*objects = append(*objects, packed)
	}

	return packed, nil
}

func indexOfPacked(objects [][]byte, b []byte) int {
	for i, o := range objects {
		if string(o) == string(b) {
			return i
		}
	}
	return -1
}

func packInt(v int64) []byte {
	switch {
	case v < 0x28:
		return []byte{byte(v) + 8}
	case v <= 0xFF:
		return []byte{0x30, byte(v)}
	case v <= 0xFFFF:
		b := []byte{0x31, 0, 0}
		binary.LittleEndian.PutUint16(b[1:], uint16(v))
		return b
	case v <= 0xFFFFFFFF:
		b := []byte{0x32, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b[1:], uint32(v))
		return b
	default:
		b := []byte{0x33, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.LittleEndian.PutUint64(b[1:], uint64(v))
		return b
	}
}

func packString(s string) []byte {
	encoded := []byte(s)
	n := len(encoded)
	switch {
	case n <= 0x20:
		return append([]byte{0x40 + byte(n)}, encoded...)
	case n <= 0xFF:
		return append([]byte{0x61, byte(n)}, encoded...)
	case n <= 0xFFFF:
		b := []byte{0x62, byte(n), byte(n >> 8)}
		return append(b, encoded...)
	case n <= 0xFFFFFF:
		b := []byte{0x63, byte(n), byte(n >> 8), byte(n >> 16)}
		return append(b, encoded...)
	default:
		b := []byte{0x64, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
		return append(b, encoded...)
	}
}

func packBytes(data []byte) []byte {
	n := len(data)
	switch {
	case n <= 0x20:
		return append([]byte{0x70 + byte(n)}, data...)
	case n <= 0xFF:
		return append([]byte{0x91, byte(n)}, data...)
	case n <= 0xFFFF:
		b := []byte{0x92, byte(n), byte(n >> 8)}
		return append(b, data...)
	default:
		b := []byte{0x93, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
		return append(b, data...)
	}
}

// Unpack deserializes OPACK bytes, returning the value and any trailing bytes.
//
// Values map to: nil, bool, int64, float64, string, []byte, UUID, []any and
// map[string]any.
func Unpack(data []byte) (any, []byte, error) {
	var objects []any
	return unpack(data, &objects)
}

func unpack(data []byte, objects *[]any) (any, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("opack: no data")
	}

	var value any
	var remaining []byte
	addToObjects := true

	tag := data[0]
	switch {
	case tag == 0x01:
		value, remaining, addToObjects = true, data[1:], false
	case tag == 0x02:
		value, remaining, addToObjects = false, data[1:], false
	case tag == 0x04:
		value, remaining, addToObjects = nil, data[1:], false
	case tag == 0x05:
		if len(data) < 17 {
			return nil, nil, errors.New("opack: short uuid")
		}
		var u UUID
		copy(u[:], data[1:17])
		value, remaining = u, data[17:]
	case tag == 0x06:
		if len(data) < 9 {
			return nil, nil, errors.New("opack: short absolute time")
		}
		value, remaining = int64(binary.LittleEndian.Uint64(data[1:9])), data[9:]
	case tag >= 0x08 && tag <= 0x2F:
		value, remaining, addToObjects = int64(tag)-8, data[1:], false
	case tag == 0x35:
		if len(data) < 5 {
			return nil, nil, errors.New("opack: short float32")
		}
		value = float64(math.Float32frombits(binary.LittleEndian.Uint32(data[1:5])))
		remaining = data[5:]
	case tag == 0x36:
		if len(data) < 9 {
			return nil, nil, errors.New("opack: short float64")
		}
		value = math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))
		remaining = data[9:]
	case tag&0xF0 == 0x30:
		n := 1 << (tag & 0xF)
		if n > 8 || len(data) < 1+n {
			return nil, nil, errors.New("opack: short integer")
		}
		var v uint64
		for i := 0; i < n; i++ {
			v |= uint64(data[1+i]) << (8 * i)
		}
		value, remaining = int64(v), data[1+n:]
	case tag >= 0x40 && tag <= 0x60:
		n := int(tag) - 0x40
		if len(data) < 1+n {
			return nil, nil, errors.New("opack: short string")
		}
		value, remaining = string(data[1:1+n]), data[1+n:]
	case tag > 0x60 && tag <= 0x64:
		lenBytes := int(tag & 0xF)
		if len(data) < 1+lenBytes {
			return nil, nil, errors.New("opack: short string length")
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n |= int(data[1+i]) << (8 * i)
		}
		if len(data) < 1+lenBytes+n {
			return nil, nil, errors.New("opack: short string")
		}
		value = string(data[1+lenBytes : 1+lenBytes+n])
		remaining = data[1+lenBytes+n:]
	case tag >= 0x70 && tag <= 0x90:
		n := int(tag) - 0x70
		if len(data) < 1+n {
			return nil, nil, errors.New("opack: short bytes")
		}
		value = append([]byte(nil), data[1:1+n]...)
		remaining = data[1+n:]
	case tag >= 0x91 && tag <= 0x94:
		lenBytes := 1 << ((tag & 0xF) - 1)
		if lenBytes > 8 || len(data) < 1+lenBytes {
			return nil, nil, errors.New("opack: short bytes length")
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n |= int(data[1+i]) << (8 * i)
		}
		if n < 0 || len(data) < 1+lenBytes+n {
			return nil, nil, errors.New("opack: short bytes")
		}
		value = append([]byte(nil), data[1+lenBytes:1+lenBytes+n]...)
		remaining = data[1+lenBytes+n:]
	case tag&0xF0 == 0xD0:
		count := int(tag & 0xF)
		var out []any
		ptr := data[1:]
		var err error
		if count == 0xF { // endless list
			for {
				if len(ptr) == 0 {
					return nil, nil, errors.New("opack: unterminated list")
				}
				if ptr[0] == 0x03 {
					ptr = ptr[1:]
					break
				}
				var item any
				item, ptr, err = unpack(ptr, objects)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, item)
			}
		} else {
			for i := 0; i < count; i++ {
				var item any
				item, ptr, err = unpack(ptr, objects)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, item)
			}
		}
		if out == nil {
			out = []any{}
		}
		value, remaining, addToObjects = out, ptr, false
	case tag&0xE0 == 0xE0:
		count := int(tag & 0xF)
		out := make(map[string]any)
		ptr := data[1:]
		var err error
		readPair := func() error {
			var key, val any
			key, ptr, err = unpack(ptr, objects)
			if err != nil {
				return err
			}
			val, ptr, err = unpack(ptr, objects)
			if err != nil {
				return err
			}
			ks, ok := key.(string)
			if !ok {
				return fmt.Errorf("opack: unsupported dict key type %T", key)
			}
			out[ks] = val
			return nil
		}
		if count == 0xF { // endless dict
			for {
				if len(ptr) == 0 {
					return nil, nil, errors.New("opack: unterminated dict")
				}
				if ptr[0] == 0x03 {
					ptr = ptr[1:]
					break
				}
				if err := readPair(); err != nil {
					return nil, nil, err
				}
			}
		} else {
			for i := 0; i < count; i++ {
				if err := readPair(); err != nil {
					return nil, nil, err
				}
			}
		}
		value, remaining, addToObjects = out, ptr, false
	case tag >= 0xA0 && tag <= 0xC0:
		idx := int(tag) - 0xA0
		if idx >= len(*objects) {
			return nil, nil, fmt.Errorf("opack: object reference %d out of range", idx)
		}
		value, remaining, addToObjects = (*objects)[idx], data[1:], false
	case tag >= 0xC1 && tag <= 0xC4:
		n := int(tag) - 0xC0
		if len(data) < 1+n {
			return nil, nil, errors.New("opack: short object reference")
		}
		idx := 0
		for i := 0; i < n; i++ {
			idx |= int(data[1+i]) << (8 * i)
		}
		if idx < 0 || idx >= len(*objects) {
			return nil, nil, fmt.Errorf("opack: object reference %d out of range", idx)
		}
		value, remaining, addToObjects = (*objects)[idx], data[1+n:], false
	default:
		return nil, nil, fmt.Errorf("opack: unsupported tag 0x%02x", tag)
	}

	if addToObjects && !containsValue(*objects, value) {
		*objects = append(*objects, value)
	}

	return value, remaining, nil
}

func containsValue(objects []any, v any) bool {
	for _, o := range objects {
		if reflect.DeepEqual(o, v) {
			return true
		}
	}
	return false
}
