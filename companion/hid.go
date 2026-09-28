package companion

// HidCommand identifies a remote-control button, matching pyatv's HidCommand
// enum.
type HidCommand int64

// HID commands.
const (
	HidUp               HidCommand = 1
	HidDown             HidCommand = 2
	HidLeft             HidCommand = 3
	HidRight            HidCommand = 4
	HidMenu             HidCommand = 5
	HidSelect           HidCommand = 6
	HidHome             HidCommand = 7
	HidVolumeUp         HidCommand = 8
	HidVolumeDown       HidCommand = 9
	HidSiri             HidCommand = 10
	HidScreensaver      HidCommand = 11
	HidSleep            HidCommand = 12
	HidWake             HidCommand = 13
	HidPlayPause        HidCommand = 14
	HidChannelIncrement HidCommand = 15
	HidChannelDecrement HidCommand = 16
	HidGuide            HidCommand = 17
	HidPageUp           HidCommand = 18
	HidPageDown         HidCommand = 19
)

// HidCommandNames maps CLI-friendly names to commands.
var HidCommandNames = map[string]HidCommand{
	"up": HidUp, "down": HidDown, "left": HidLeft, "right": HidRight,
	"menu": HidMenu, "select": HidSelect, "home": HidHome,
	"volume_up": HidVolumeUp, "volume_down": HidVolumeDown, "siri": HidSiri,
	"screensaver": HidScreensaver, "sleep": HidSleep, "wake": HidWake,
	"play_pause": HidPlayPause, "channel_up": HidChannelIncrement,
	"channel_down": HidChannelDecrement, "guide": HidGuide,
	"page_up": HidPageUp, "page_down": HidPageDown,
}

// PowerState is the coarse device power state derived from SystemStatus.
type PowerState int

// Power states.
const (
	PowerStateUnknown PowerState = iota
	PowerStateOff
	PowerStateOn
)

func (p PowerState) String() string {
	switch p {
	case PowerStateOff:
		return "off"
	case PowerStateOn:
		return "on"
	default:
		return "unknown"
	}
}

// SystemStatus values reported by tvOS ("state" in SystemStatus events).
const (
	systemStatusAsleep      = 0x01
	systemStatusScreensaver = 0x02
	systemStatusAwake       = 0x03
	systemStatusIdle        = 0x04
)

func systemStatusToPowerState(state int64) PowerState {
	switch state {
	case systemStatusAsleep:
		return PowerStateOff
	case systemStatusScreensaver, systemStatusAwake, systemStatusIdle:
		return PowerStateOn
	default:
		return PowerStateUnknown
	}
}
