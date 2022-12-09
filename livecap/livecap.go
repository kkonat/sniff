package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// in windows to obtain device names use: getmac /fo csv /v
var device = ``

var filter = flag.String("filter", "", "BPF filter for capture")
var iface = flag.String("iface", device, "Select interface where to capture")
var snaplen = flag.Int("snaplen", 1024, "Maximun sise to read for each packet")
var promisc = flag.Bool("promisc", false, "Enable promiscuous mode")
var timeoutT = flag.Int("timeout", 10, "Connection Timeout in seconds")

func main() {
	log.Println("start")
	defer log.Println("end")

	flag.Parse()

	var timeout time.Duration = time.Duration(*timeoutT) * time.Second

	// Opening Device
	devices, err := pcap.FindAllDevs()
	iface = &(devices[4].Name)
	log.Println("Opening:", *iface)
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Applying BPF Filter if it exists
	if *filter != "" {
		log.Println("applying filter ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("error applyign BPF Filter %s - %v", *filter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
