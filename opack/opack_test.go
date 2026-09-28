package opack

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Byte vectors from pyatv's tests/support/test_opack.py.
func TestPackScalars(t *testing.T) {
	cases := []struct {
		in   any
		want []byte
	}{
		{true, []byte{0x01}},
		{false, []byte{0x02}},
		{nil, []byte{0x04}},
		{0, []byte{0x08}},
		{0xF, []byte{0x17}},
		{0x27, []byte{0x2F}},
		{0x28, []byte{0x30, 0x28}},
		{0x1FF, []byte{0x31, 0xFF, 0x01}},
		{0x1FFFFFF, []byte{0x32, 0xFF, 0xFF, 0xFF, 0x01}},
		{int64(0x1FFFFFFFFFFFFFF), []byte{0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}},
	}
	for _, tc := range cases {
		got, err := Pack(tc.in)
		if err != nil {
			t.Fatalf("Pack(%v): %v", tc.in, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("Pack(%v) = %x, want %x", tc.in, got, tc.want)
		}
	}
}

func TestPackUUID(t *testing.T) {
	u := UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78}
	got, err := Pack(u)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x05}, u[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("Pack(uuid) = %x, want %x", got, want)
	}
}

func TestPackStringsAndBytes(t *testing.T) {
	got, err := Pack("test")
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{0x44}, []byte("test")...); !bytes.Equal(got, want) {
		t.Errorf("Pack(string) = %x, want %x", got, want)
	}

	got, err = Pack([]byte{0xAC, 0xE0})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x72, 0xAC, 0xE0}; !bytes.Equal(got, want) {
		t.Errorf("Pack(bytes) = %x, want %x", got, want)
	}
}

func TestPackNegativeUnsupported(t *testing.T) {
	if _, err := Pack(-1); err == nil {
		t.Error("expected error for negative integer")
	}
}

// Object-list deduplication: pyatv packs ["dup", "dup"] with a 0xA0 back
// reference for the second element.
func TestPackDeduplication(t *testing.T) {
	got, err := Pack([]any{"dup", "dup"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xD2, 0x43, 'd', 'u', 'p', 0xA0}
	if !bytes.Equal(got, want) {
		t.Errorf("Pack = %x, want %x", got, want)
	}

	value, rest, err := Unpack(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes: %x", rest)
	}
	if !reflect.DeepEqual(value, []any{"dup", "dup"}) {
		t.Errorf("Unpack = %#v", value)
	}
}

func TestRoundTripMessage(t *testing.T) {
	message := map[string]any{
		"_i": "_systemInfo",
		"_t": int64(2),
		"_x": int64(4660),
		"_c": map[string]any{
			"name":  "goatv",
			"model": "iPhone10,6",
			"_bf":   int64(0),
		},
	}
	packed, err := Pack(message)
	if err != nil {
		t.Fatal(err)
	}
	value, rest, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes: %x", rest)
	}
	if !reflect.DeepEqual(value, message) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v", value, message)
	}
}

func TestRoundTripEndlessCollections(t *testing.T) {
	list := make([]any, 20)
	for i := range list {
		// Distinct strings (>1 byte packed) to exercise the object list.
		list[i] = string(rune('A'+i)) + "x"
	}
	packed, err := Pack(list)
	if err != nil {
		t.Fatal(err)
	}
	if packed[0] != 0xDF {
		t.Errorf("expected endless list marker, got %x", packed[0])
	}
	if packed[len(packed)-1] != 0x03 {
		t.Errorf("expected terminator, got %x", packed[len(packed)-1])
	}
	value, _, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, list) {
		t.Errorf("round trip mismatch: %#v", value)
	}

	dict := make(map[string]any, 16)
	for i := 0; i < 16; i++ {
		dict[string(rune('a'+i))+"k"] = int64(i)
	}
	packed, err = Pack(dict)
	if err != nil {
		t.Fatal(err)
	}
	value, _, err = Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, dict) {
		t.Errorf("round trip mismatch: %#v", value)
	}
}

// Vector captured from pyatv: pack({"_i": "_hidC", "_t": 2, "_x": 1,
// "_c": {"_hBtS": 1, "_hidC": 13}}) with keys in that insertion order.
// Verifies our Unpack against pyatv's Pack output.
func TestUnpackPyatvVector(t *testing.T) {
	data, err := hex.DecodeString(
		"e4" + // dict, 4 entries
			"425f69" + "455f68696443" + // "_i": "_hidC"
			"425f74" + "0a" + // "_t": 2
			"425f78" + "09" + // "_x": 1
			"425f63" + // "_c":
			"e2" + // dict, 2 entries
			"455f68427453" + "09" + // "_hBtS": 1
			"a1" + "15") // "_hidC" (ref to "_hidC" string), 13
	if err != nil {
		t.Fatal(err)
	}
	value, rest, err := Unpack(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes: %x", rest)
	}
	want := map[string]any{
		"_i": "_hidC",
		"_t": int64(2),
		"_x": int64(1),
		"_c": map[string]any{"_hBtS": int64(1), "_hidC": int64(13)},
	}
	if !reflect.DeepEqual(value, want) {
		t.Errorf("Unpack = %#v, want %#v", value, want)
	}
}

func TestUnpackSizedIntegers(t *testing.T) {
	cases := []struct {
		data []byte
		want int64
	}{
		{[]byte{0x30, 0xFF}, 0xFF},
		{[]byte{0x31, 0x01, 0x02}, 0x0201},
		{[]byte{0x32, 0x01, 0x02, 0x03, 0x04}, 0x04030201},
		{[]byte{0x33, 1, 2, 3, 4, 5, 6, 7, 0}, 0x0007060504030201},
	}
	for _, tc := range cases {
		value, _, err := Unpack(tc.data)
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Errorf("Unpack(%x) = %v, want %v", tc.data, value, tc.want)
		}
	}
}
