// This is the packet helper. Anything dealing with packets will be dealt with here!
package main

import (
	"errors"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	ETH_SNAPLEN = 1600
	ETH_PROMISC = true
	ETH_TIMEOUT = pcap.BlockForever

)

var (
	// Ethernet Layer
	CP_SRC_MAC = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	CP_DST_MAC = net.HardwareAddr{0x88, 0x88, 0x88, 0x88, 0x88, 0x88}

	// IPv4 Layer
	CP_SRC_IP = net.IP{10, 0, 0, 2}
	CP_DST_IP = net.IP{10, 0, 0, 3}
	CP_VERSION_IP = 4
	CP_IHL_IP = 5
	CP_TTL_IP = 1
	CP_PROTO_IP = layers.IPProtocolUDP


	CP_ETH_LAYER = &layers.Ethernet {
		SrcMAC: CP_SRC_MAC,
		DstMAC: CP_DST_MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	CP_IPv4_LAYER = &layers.IPv4{
		SrcIP: CP_SRC_IP,
		DstIP: CP_DST_IP,
		Version: uint8(CP_VERSION_IP),
		IHL: uint8(CP_IHL_IP),
		TTL: uint8(CP_TTL_IP),
		Protocol: CP_PROTO_IP,
		Flags: 0x0,
		FragOffset: 0x0,
	}

	CP_UDP_LAYER = &layers.UDP{
		SrcPort: 8081,
		DstPort: 8082,
	}
)

type EthernetHelper struct {
	InterfaceName string
	Handle *pcap.Handle
}

//
// Functions for Var Setting
//
func (e *EthernetHelper) SetName(name string) {
	e.InterfaceName = name
}

//
// Helper Functions
//
func (e *EthernetHelper) ParseDevicesForEth() (string, error) {
	iflist, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, iface := range iflist {
		if strings.Contains(iface.Name, "eth") {
			return iface.Name, nil
		}
	}

	return "random", errors.New("no devices to parse related to eth")
}

func (e *EthernetHelper) openStream() (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(e.InterfaceName, ETH_SNAPLEN, ETH_PROMISC, ETH_TIMEOUT)
	return handle, err
}

//
// Functions for Interfacing
//
func (e *EthernetHelper) AutoOpenStream() {
	ifname, err := e.ParseDevicesForEth()
	if err != nil {
		panic(err)
	}

	e.SetName(ifname);
	handle, err := e.openStream()
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("udp")
	if err != nil {
		panic(err)
	}
}

func (e *EthernetHelper) AcquirePacketChannel() (*gopacket.PacketSource) {
	return gopacket.NewPacketSource(e.Handle, e.Handle.LinkType())
}

func (e *EthernetHelper) WritePacket(cp CanPack) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, 
		CP_ETH_LAYER,
		CP_IPv4_LAYER,
		CP_UDP_LAYER,
		gopacket.Payload(cp.ToByte()))

	e.Handle.WritePacketData(buf.Bytes())
}
