// https://medium.com/a-bit-off/sniffing-network-go-6753cae91d3f
package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("error retrieving devices - %v", err)
	}

	for i, device := range devices {
		fmt.Printf("%d.", i)
		fmt.Printf("\tDevice Name: %s\n", device.Name)
		fmt.Printf("\tDevice Description: %s\n", device.Description)
		fmt.Printf("\tDevice Flags: %d\n", device.Flags)
		for _, iaddress := range device.Addresses {
			fmt.Printf("\t\tInterface IP: %s\n", iaddress.IP)
			fmt.Printf("\t\tInterface NetMask: %s\n", iaddress.Netmask)
		}
	}
}
