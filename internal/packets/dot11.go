package packets

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	openFlags      = 1057
	wpaFlags       = 1041
	specManFlag    = 1 << 8
	durationID     = uint16(0x013a)
	capabilityInfo = uint16(0x0411)
	listenInterval = uint16(3)
	//1-54 Mbit
	fakeApRates  = []byte{0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01}
	fakeApWpaRSN = []byte{
		0x01, 0x00, // RSN Version 1
		0x00, 0x0f, 0xac, 0x02, // Group Cipher Suite : 00-0f-ac TKIP
		0x02, 0x00, // 2 Pairwise Cipher Suites (next two lines)
		0x00, 0x0f, 0xac, 0x04, // AES Cipher / CCMP
		0x00, 0x0f, 0xac, 0x02, // TKIP Cipher
		0x01, 0x00, // 1 Authentication Key Management Suite (line below)
		0x00, 0x0f, 0xac, 0x02, // Pre-Shared Key
		0x00, 0x00,
	}
	wpaSignatureBytes = []byte{0, 0x50, 0xf2, 1}

	assocRates        = []byte{0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c}
	assocESRates      = []byte{0x0C, 0x12, 0x18, 0x60}
	assocRSNInfo      = []byte{0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x8C, 0x00}
	assocCapabilities = []byte{0x2C, 0x01, 0x03, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	broadcastHw       = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Dot11ApConfig struct {
	SSID               string
	BSSID              net.HardwareAddr
	Channel            int
	Encryption         bool
	SpectrumManagement bool
}

func Dot11Chan2Freq(channel int) int {
	if channel <= 13 {
		return ((channel - 1) * 5) + 2412
	} else if channel == 14 {
		return 2484
	} else if channel <= 173 {
		return ((channel - 7) * 5) + 5035
	} else if channel == 177 {
		return 5885
	}

	return 0
}

func NewDot11Beacon(conf Dot11ApConfig, seq uint16, extendDot11Info ...*layers.Dot11InformationElement) (error, []byte) {
	flags := openFlags
	if conf.Encryption {
		flags = wpaFlags
	}
	if conf.SpectrumManagement {
		flags |= specManFlag
	}
	stack := []gopacket.SerializableLayer{
		&layers.RadioTap{
			DBMAntennaSignal: int8(-10),
			ChannelFrequency: layers.RadioTapChannelFrequency(Dot11Chan2Freq(conf.Channel)),
		},
		&layers.Dot11{
			Address1:       broadcastHw,
			Address2:       conf.BSSID,
			Address3:       conf.BSSID,
			Type:           layers.Dot11TypeMgmtBeacon,
			SequenceNumber: seq,
		},
		&layers.Dot11MgmtBeacon{
			Flags:    uint16(flags),
			Interval: 100,
		},
		Dot11Info(layers.Dot11InformationElementIDSSID, []byte(conf.SSID)),
		Dot11Info(layers.Dot11InformationElementIDRates, fakeApRates),
		Dot11Info(layers.Dot11InformationElementIDDSSet, []byte{byte(conf.Channel & 0xff)}),
	}
	for _, v := range extendDot11Info {
		stack = append(stack, v)
	}
	if conf.Encryption {
		stack = append(stack, &layers.Dot11InformationElement{
			ID:     layers.Dot11InformationElementIDRSNInfo,
			Length: uint8(len(fakeApWpaRSN) & 0xff),
			Info:   fakeApWpaRSN,
		})
	}

	return Serialize(stack...)
}

func Dot11Info(id layers.Dot11InformationElementID, info []byte) *layers.Dot11InformationElement {
	return &layers.Dot11InformationElement{
		ID:     id,
		Length: uint8(len(info) & 0xff),
		Info:   info,
	}
}

func BuildDot11ApConfig() Dot11ApConfig {
	ssid := "I still love Ruby, don't worry!"
	bssid, _ := net.ParseMAC("pi:ca:tw:as:he:re")
	channel := 1
	encryption := false

	config := Dot11ApConfig{
		SSID:       ssid,
		BSSID:      bssid,
		Channel:    channel,
		Encryption: encryption,
	}

	return config
}
