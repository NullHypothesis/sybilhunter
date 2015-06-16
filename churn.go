// Analyse churn rate of a set of consensuses.
package main

import (
	"fmt"
	"log"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// AnalyseChurn analyses the churn of a set of router statuses.  In particular,
// it checks if the amount of previously unobserved router statuses exceeds the
// given threshold.  This is a reimplementation of doctor's sybil_checker
// script: <https://gitweb.torproject.org/doctor.git/tree/sybil_checker.py>
func AnalyseChurn(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	var allStatuses = tor.NewConsensus()
	var status *tor.Consensus

	for objects := range channel {

		switch v := objects.(type) {
		case *tor.Consensus:
			status = v
		default:
			log.Fatalln("Only router status files are supported for churn analysis.")
		}

		if allStatuses.Length() > 0 {
			newStatuses := status.Subtract(allStatuses)
			if newStatuses.Length() >= params.Threshold {
				fmt.Printf("Observed change in consensus \"valid-after %s\" is %d.\n",
					status.ValidAfter, newStatuses.Length())
			}
		}

		// Only keep track of fingerprints and discard the router statuses
		// because we don't need them.
		for fingerprint, _ := range status.RouterStatuses {
			allStatuses.Set(fingerprint, nil)
		}
	}
}
