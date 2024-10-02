package spoofer

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jaqarrick/bspoof/internal/packets"
)

func SpoofBeacon() {
	conf := packets.BuildDot11ApConfig()
	seq := uint16(0)
	err, bytes := packets.NewDot11Beacon(conf, seq)

	if err != nil {
		fmt.Println("unable to create new dot11 beacon", err)
	}

	if len(bytes) <= 0 {
		fmt.Println("unable to create new dot11 beacon")
	}
	fmt.Println("Spoofing Beacon")
	fmt.Println("Bytes: ", bytes)

	// // Open the network interface
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a packet from the beacon frame bytes
	packet := gopacket.NewPacket(bytes, gopacket.LayerTypePayload, gopacket.Default)

	fmt.Println("Packet: ", packet)
	fmt.Println("Packet Bytes: ", packet.Data())

	// // Find all devices
	// devices, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // Print device information
	// fmt.Println("Devices found:")
	// for _, device := range devices {
	// 	fmt.Println("\nName: ", device.Name)
	// 	fmt.Println("Description: ", device.Description)
	// 	fmt.Println("Devices addresses: ", device.Description)
	// 	for _, address := range device.Addresses {
	// 		fmt.Println("- IP address: ", address.IP)
	// 		fmt.Println("- Subnet mask: ", address.Netmask)
	// 	}
	// }

	// Send the packet
	err = handle.WritePacketData(packet.Data())
	if err != nil {
		log.Fatal(err)
	}

}
