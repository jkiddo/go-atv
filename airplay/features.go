package airplay

import (
	"fmt"
	"strconv"
	"strings"
)

// Features is the AirPlay feature bitmask announced over mDNS ("features" or
// "ft" TXT property). Only the flags goatv needs are named here; see
// https://openairplay.github.io/airplay-spec/features.html for the full list.
type Features uint64

const (
	FeatureVideoV1                               Features = 1 << 0
	FeatureSupportsUnifiedMediaControl           Features = 1 << 38
	FeatureSupportsSystemPairing                 Features = 1 << 43
	FeatureSupportsCoreUtilsPairingAndEncryption Features = 1 << 48
	FeatureVideoV2                               Features = 1 << 49
)

// parseFeatures parses a feature string of the form "0x12345678" or
// "0x12345678,0xabcdef12" (the second part holds the upper 32 bits).
func parseFeatures(s string) (Features, error) {
	lower, upper, hasUpper := strings.Cut(s, ",")
	value, err := parseHex(lower)
	if err != nil {
		return 0, fmt.Errorf("airplay: invalid feature string %q", s)
	}
	if hasUpper {
		high, err := parseHex(upper)
		if err != nil {
			return 0, fmt.Errorf("airplay: invalid feature string %q", s)
		}
		value |= high << 32
	}
	return Features(value), nil
}

func parseHex(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	return strconv.ParseUint(s, 16, 64)
}

// deviceFeatures extracts the feature flags from mDNS TXT properties
// ("features" with fallback to "ft").
func deviceFeatures(properties map[string]string) Features {
	value := properties["features"]
	if value == "" {
		value = properties["ft"]
	}
	if value == "" {
		return 0
	}
	features, err := parseFeatures(value)
	if err != nil {
		return 0
	}
	return features
}

// SupportsPlayURL reports whether the receiver announces AirPlay video.
func (f Features) SupportsPlayURL() bool {
	return f&(FeatureVideoV1|FeatureVideoV2) != 0
}

// supportsTransient reports whether the receiver supports transient pairing
// (pair-setup without PIN), mirroring pyatv's extract_credentials.
func (f Features) supportsTransient() bool {
	return f&(FeatureSupportsSystemPairing|FeatureSupportsCoreUtilsPairingAndEncryption) != 0
}

// isVersion2 reports whether the receiver speaks AirPlay 2, mirroring
// pyatv's get_protocol_version heuristic.
func (f Features) isVersion2() bool {
	return f&(FeatureSupportsUnifiedMediaControl|FeatureSupportsCoreUtilsPairingAndEncryption) != 0
}
