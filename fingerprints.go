// Looks for relays manipulating their fingerprints.

package main

import (
	"fmt"
	"log"
	"sort"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

type ValueSorter struct {
	// IP addresses in string format.
	keys []string
	// Amount of unique fingerprints.
	vals []int
}

// Implement the sort interface (1/3).
func (vs ValueSorter) Len() int {
	return len(vs.keys)
}

// Implement the sort interface (2/3).
func (vs ValueSorter) Swap(i int, j int) {
	vs.keys[i], vs.keys[j] = vs.keys[j], vs.keys[i]
	vs.vals[i], vs.vals[j] = vs.vals[j], vs.vals[i]
}

// Implement the sort interface (3/3).
func (vs ValueSorter) Less(i int, j int) bool {
	return vs.vals[i] < vs.vals[j]
}

// Used to count how often a given fingerprint was observed.
type FprStats map[tor.Fingerprint]int

// countFingerprints updates the fingerprint statistics with the given
// fingerprint and address.
func countFingerprints(fpr tor.Fingerprint, address string, analysis map[string]FprStats) {

	fprStats, ok := analysis[address]
	if ok {
		_, ok := fprStats[fpr]
		if ok {
			// Fingerprint already present for address: update counter.
			fprStats[fpr] += 1
		} else {
			// Fingerprint new: add it to the map.
			fprStats[fpr] = 1
		}
	} else {
		analysis[address] = FprStats{fpr: 1}
	}
}

// AnalyseFingerprints determines how many unique fingerprints were used by all
// Tor relays in the given object set.
func AnalyseFingerprints(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	// Go does not like net.IP as a map key.  So we use an IP address's string
	// representation instead.
	var fprAnalysis map[string]FprStats = map[string]FprStats{}

	for objects := range channel {
		switch v := objects.(type) {
		case *tor.Consensus:
			for fpr, getVal := range v.RouterStatuses {
				countFingerprints(fpr, getVal().Address.String(), fprAnalysis)
			}
		case *tor.RouterDescriptors:
			for fpr, getVal := range v.RouterDescriptors {
				countFingerprints(fpr, getVal().Address.String(), fprAnalysis)
			}
		}
	}

	vs := ValueSorter{
		keys: make([]string, 0),
		vals: make([]int, 0),
	}

	// Use ValueSorter to sort by IP addresses with most unique fingerprints.
	log.Println("Now sorting by IP addresses with most unique fingerprints.")
	for ipAddr, fprList := range fprAnalysis {
		vs.keys = append(vs.keys, ipAddr)
		vs.vals = append(vs.vals, len(fprList))
	}
	sort.Sort(vs)

	for i, val := range vs.keys {
		fmt.Printf("%s (%d unique fingerprints)\n", val, vs.vals[i])
		for fingerprint, count := range fprAnalysis[val] {
			fmt.Printf("\t%s (seen %d times)\n", fingerprint, count)
		}
	}
}
