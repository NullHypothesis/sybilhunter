// Determine relays that contribute n% of the overall bandwidth.

package main

import (
	"fmt"
	"log"
	"sort"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// SortRelays stores relay fingerprints and their respective bandwidth values.
// The struct is used to sort by bandwidth.
type SortRelays struct {
	Fingerprints []tor.Fingerprint
	Bandwidths   []uint64
}

// Implement the sort interface (1/3).
func (sr SortRelays) Len() int {
	return len(sr.Fingerprints)
}

// Implement the sort interface (2/3).
func (sr SortRelays) Swap(i int, j int) {
	sr.Fingerprints[i], sr.Fingerprints[j] = sr.Fingerprints[j], sr.Fingerprints[i]
	sr.Bandwidths[i], sr.Bandwidths[j] = sr.Bandwidths[j], sr.Bandwidths[i]
}

// Implement the sort interface (3/3).
func (sr SortRelays) Less(i int, j int) bool {
	return sr.Bandwidths[i] < sr.Bandwidths[j]
}

// Determine and print which relays provide the given fraction of bandwidth in
// the given consensus.
func DetermineRelays(consensus *tor.Consensus, fraction float64) {

	// Populate our struct that's used for sorting relays by bandwidth.
	totalBw := uint64(0)
	sr := SortRelays{make([]tor.Fingerprint, 0), make([]uint64, 0)}
	for fingerprint, getStatus := range consensus.RouterStatuses {
		status := getStatus()
		totalBw += status.Bandwidth
		sr.Fingerprints = append(sr.Fingerprints, fingerprint)
		sr.Bandwidths = append(sr.Bandwidths, status.Bandwidth)
	}
	log.Printf("Total consensus bandwidth: %d\n", totalBw)
	sort.Sort(sr)

	threshold := fraction * float64(totalBw)
	log.Printf("Bandwidth threshold %.2f (%.2f%%)\n", threshold, fraction*100)

	relayCount := 0
	bwCount := uint64(0)
	fmt.Println("fingerprint,ip_addr,bandwidth")
	// Iterate over relays, high-bandwidth to low-bandwidth.
	for i := len(sr.Fingerprints) - 1; i >= 0; i-- {
		bwCount += sr.Bandwidths[i]
		if float64(bwCount) <= threshold {
			status, exists := consensus.Get(sr.Fingerprints[i])
			if !exists {
				log.Fatalf("Couldn't find relay %s anymore?\n", sr.Fingerprints[i])
			}
			fmt.Printf("%s,%s,%d\n", sr.Fingerprints[i], status.Address, sr.Bandwidths[i])
			relayCount++
		} else {
			break
		}
	}

	relayFraction := float32(relayCount) / float32(consensus.Length()) * 100
	log.Printf("%d out of %d relays (%.2f%%) provide %.2f%% of the overall bandwidth.\n",
		relayCount, consensus.Length(), relayFraction, fraction*100)
}

// FindFastRelays determines which relays are responsible for n% of the total
// network bandwidth.
func FindFastRelays(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	// Iterate over all consensus files.
	for objects := range channel {
		DetermineRelays(objects.(*tor.Consensus), params.BwFraction)
	}
}
