// Pretty-print objects for easy grepping.

package main

import (
	"fmt"
	"log"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

var printedBanner bool = false

// PrintInfo prints a router status.  If we also have access to router
// descriptors, we print those too.
func PrintInfo(descriptorDir string, status *tor.RouterStatus) {

	desc, err := tor.LoadDescriptorFromDigest(descriptorDir, status.Digest, status.Publication)
	if err == nil {
		if !printedBanner {
			fmt.Println("fingerprint,nickname,ip_addr,or_port,dir_port,flags,published,version,platform,bandwidthavg,bandwidthburst,uptime,familysize")
			printedBanner = true
		}
		fmt.Printf("%s, %s, %d, %d, %d, %d\n", status, desc.OperatingSystem, desc.BandwidthAvg, desc.BandwidthBurst, desc.Uptime, len(desc.Family))
	} else {
		if !printedBanner {
			fmt.Println("fingerprint,nickname,ip_addr,or_port,dir_port,flags,published,version")
			printedBanner = true
		}
		fmt.Println(status)
	}
}

// PrettyPrint prints all objects within the object sets received over the
// given channel.  The output is meant to be human-readable and easy to analyse
// and grep.
func PrettyPrint(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	counter := 0
	for objects := range channel {
		for object := range objects.Iterate() {
			counter += 1

			switch obj := object.(type) {
			case *tor.RouterStatus:
				PrintInfo(params.DescriptorDir, obj)
			case *tor.RouterDescriptor:
				fmt.Println(obj)
			}
		}
	}
	log.Printf("Printed %d objects.\n", counter)
}
