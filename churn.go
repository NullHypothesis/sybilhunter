// Analyse churn rate of a set of consensuses.
package main

import (
	"fmt"
	"log"
	"math"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// consensusTime returns a prettily-formatted string, showing the consensus'
// valid-after time.
func consensusTime(consensus *tor.Consensus) string {

	return consensus.ValidAfter.Format("2006-01-02-15-00-00")
}

// dumpChurnRelays dumps the given relays to stdout for manual analysis.
func dumpChurnRelays(goneRelays, newRelays *tor.Consensus) {

	// Sort relays by nickname.
	nickname := func(relay1, relay2 tor.GetStatus) bool {
		return relay1().Nickname < relay2().Nickname
	}

	gone := goneRelays.ToSlice()
	By(nickname).Sort(gone)
	fresh := newRelays.ToSlice()
	By(nickname).Sort(fresh)

	for _, getStatus := range gone {
		fmt.Printf("- <https://atlas.torproject.org/#details/%s> %s\n",
			getStatus().Fingerprint, getStatus().Nickname)
	}
	fmt.Println()
	for _, getStatus := range fresh {
		fmt.Printf("+ <https://atlas.torproject.org/#details/%s> %s\n",
			getStatus().Fingerprint, getStatus().Nickname)
	}
}

// determineChurn determines and returns the churn rate of the two given
// subsequent consensuses.  For the churn rate, we use the formula shown in
// Section 2.1 of: <http://www.cs.berkeley.edu/~istoica/papers/2006/churn.pdf>.
func determineChurn(prevConsensus, newConsensus *tor.Consensus) float64 {

	goneRelays := prevConsensus.Subtract(newConsensus)
	newRelays := newConsensus.Subtract(prevConsensus)

	total := goneRelays.Length() + newRelays.Length()
	max := math.Max(float64(prevConsensus.Length()), float64(newConsensus.Length()))
	churn := (float64(total) / max) / 2

	fmt.Printf("Churn between %s and %s is %.5f (%d gone, %d new).\n",
		consensusTime(newConsensus), consensusTime(prevConsensus), churn,
		goneRelays.Length(), newRelays.Length())

	return churn
}

// AnalyseChurn determines the churn rate of a set of consecutive consensuses.
// If the churn rate exceeds the given threshold, all new and disappeared relays
// are dumped to stdout.
func AnalyseChurn(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	var newConsensus *tor.Consensus
	var prevConsensus = tor.NewConsensus()

	// Every loop iteration processes one consensus.  We compare consensus t
	// with consensus t - 1.
	for objects := range channel {

		switch obj := objects.(type) {
		case *tor.Consensus:
			newConsensus = obj
		default:
			log.Fatalln("Only router status files are supported for churn analysis.")
		}

		if prevConsensus.Length() == 0 {
			prevConsensus = newConsensus
			continue
		}

		churn := determineChurn(prevConsensus, newConsensus)
		if churn >= params.Threshold {
			goneRelays := prevConsensus.Subtract(newConsensus)
			newRelays := newConsensus.Subtract(prevConsensus)
			dumpChurnRelays(goneRelays, newRelays)
		}

		prevConsensus = newConsensus
	}
}
