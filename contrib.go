// Determine the bandwidth contribution of the given relays.

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// NetblockMap maps a network name to a set of netblocks.
type NetblockMap map[string][]*net.IPNet

// Contribution keeps track of the bandwidth contribution of a network name.
type Contribution map[string]uint64

// Contains returns true if the given netblock map contains the given IP
// address.  The lookup is very inefficient, but has to do for now.
func (nbm NetblockMap) Contains(ipAddr net.IP) bool {

	for _, netblocks := range nbm {
		for _, netblock := range netblocks {
			if netblock.Contains(ipAddr) {
				return true
			}
		}
	}

	return false
}

// ParseNetblocks parses the given file name, and extracts and returns all
// netblocks contained within.  Lines starting with "#" are interpreted as
// netblock names.  All subsequent netblocks are stored under that name.
func ParseNetblocks(fileName string) NetblockMap {

	log.Printf("Attempting to parse file %s.", fileName)

	fd, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	netblocks := make(map[string][]*net.IPNet)
	netname := "default"
	scanner := bufio.NewScanner(fd)

	for scanner.Scan() {
		line := scanner.Text()

		// New netblock name.
		if strings.HasPrefix(line, "#") {
			netname = strings.TrimSpace(line[1:])
			continue
		}

		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			log.Fatal(err)
		}
		netblocks[netname] = append(netblocks[netname], ipnet)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for netname, netblocks := range netblocks {
		log.Printf("Parsed %d IP address blocks for %s.\n", len(netblocks), netname)
	}

	return netblocks
}

// BandwidthContribution determines the bandwidth contribution made by Tor
// relays whose IP address is in the given netblocks.
func BandwidthContribution(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	var totalBw, totalCount, cloudBw, cloudCount uint64
	netblockMap := ParseNetblocks(params.InputData)
	contribution := make(Contribution)
	for netname, _ := range netblockMap {
		contribution[netname] = 0
	}

	fmt.Println("cloudcount, totalcount, cloudbw, totalbw, bwfraction")

	// Iterate over all consensuses.
	for objects := range channel {

		totalBw = 0
		cloudBw = 0
		totalCount = 0
		cloudCount = 0

		// Iterate over single relays in consensus.
		switch v := objects.(type) {
		case *tor.Consensus:
			for _, getStatus := range v.RouterStatuses {

				status := getStatus()
				totalBw += status.Bandwidth
				totalCount += 1

				for netname, netblocks := range netblockMap {
					for _, netblock := range netblocks {
						// Is the relay cloud-hosted?
						if netblock.Contains(status.Address) {
							contribution[netname] += status.Bandwidth
							cloudBw += status.Bandwidth
							cloudCount += 1
						}
					}
				}
			}
		case *tor.RouterDescriptors:
			log.Fatalln("Router descriptors not supported.")
		}

		bwfraction := float32(cloudBw) / float32(totalBw)
		fmt.Printf("%d, %d, %d, %d, %.3f\n", cloudCount, totalCount, cloudBw, totalBw, bwfraction)
	}

	for netname, bw := range contribution {
		log.Printf("%s contributed %d of bandwidth.\n", netname, bw)
	}
}
