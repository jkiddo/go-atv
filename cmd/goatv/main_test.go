package main

import (
	"reflect"
	"testing"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/companion"
)

func TestMergeDiscoveredDevices(t *testing.T) {
	companionDevices := []companion.Device{
		{Name: "Living Room", IP: "192.0.2.10", Port: 49152, Model: "AppleTV11,1"},
	}
	airplayDevices := []airplay.Device{
		{Name: "Living Room", IP: "192.0.2.10", Port: 7000, Properties: map[string]string{"model": "AppleTV11,1"}},
		{Name: "Apple TV", IP: "192.0.2.20", Port: 7000, Properties: map[string]string{"model": "AppleTV3,2"}},
	}

	got := mergeDiscoveredDevices(companionDevices, airplayDevices)
	want := []discoveredDevice{
		{Name: "Apple TV", IP: "192.0.2.20", Model: "AppleTV3,2", AirPlayPort: 7000},
		{Name: "Living Room", IP: "192.0.2.10", Model: "AppleTV11,1", CompanionPort: 49152, AirPlayPort: 7000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeDiscoveredDevices() = %#v, want %#v", got, want)
	}

	if got[0].protocols() != "airplay:7000" {
		t.Fatalf("protocols() = %q, want airplay:7000", got[0].protocols())
	}
	if got[1].protocols() != "companion:49152, airplay:7000" {
		t.Fatalf("protocols() = %q", got[1].protocols())
	}
}

func TestDiscoveredDeviceUnknownModel(t *testing.T) {
	if got := (discoveredDevice{}).model(); got != "unknown model" {
		t.Fatalf("model() = %q, want unknown model", got)
	}
}
