// Algorithms to determine nearest neighbours for Tor relays.
package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	tor "git.torproject.org/user/phw/zoossh.git"
	vptree "github.com/DataWraith/vptree"
)

type FingerprintMap map[tor.Fingerprint]bool

// QuadraticComparison determines pairwise relay similarities for all relays in
// the given object set.  If the given threshold is not 0, only relay pairs
// whose distance fall under the threshold are printed to stdout.  distFunc is
// used as distance function.
func QuadraticComparison(objects tor.ObjectSet, distFunc Distance, threshold float32) {

	// Turn the relays' fingerprints into a list.
	size := objects.Length()
	fprs := make([]tor.Fingerprint, size)

	i := 0
	for obj := range objects.Iterate(nil) {
		fprs[i] = obj.GetFingerprint()
		i++
	}

	// Compute pairwise relay similarities.
	for i := 0; i < size; i++ {

		fpr1 := fprs[i]
		for j := i + 1; j < size; j++ {

			fpr2 := fprs[j]
			obj1, _ := objects.GetObject(fpr1)
			obj2, _ := objects.GetObject(fpr2)

			distance := distFunc(obj1, obj2)

			if (threshold == 0) || (distance < threshold) {
				fmt.Printf("Dist(%s, %s) : %.3f\n", fpr1[:8], fpr2[:8], distance)
			}
		}
	}
}

// VantagePointTreeSearch builds a vantage point tree out of the given objects.
// It then attempts to find the nearest neighbours to the given relay
// identified by its fingerprint.  The result is printed to stdout.
func VantagePointTreeSearch(objects tor.ObjectSet, params *CmdLineParams) (FingerprintMap, error) {

	rootrelay := tor.Fingerprint(params.ReferenceRelay)
	neighbours := params.Neighbours

	foundNeighbours := make(FingerprintMap)

	// Find the relay whose distance to all other relays is to be determined.
	targetRelay, found := objects.GetObject(tor.SanitiseFingerprint(rootrelay))
	if !found {
		return nil, fmt.Errorf("Could not find relay with fingerprint %s.", rootrelay)
	}

	// Convert object set to interface{} slice because that's what the
	// levenshtein package expects.
	objSlice := make([]interface{}, objects.Length())
	i := 0
	for obj := range objects.Iterate(params.Filter) {
		objSlice[i] = interface{}(obj)
		i++
	}

	// We need a wrapper for Levenshtein() because the levenshtein package's
	// function signature differs from our Distance type.
	lvnst := func(stat1, stat2 interface{}) float64 {
		status1 := stat1.(*tor.RouterStatus)
		status2 := stat2.(*tor.RouterStatus)
		desc1, _ := tor.LoadDescriptorFromDigest(params.DescriptorDir, status1.Digest, status1.Publication)
		desc2, _ := tor.LoadDescriptorFromDigest(params.DescriptorDir, status2.Digest, status2.Publication)
		return float64(Levenshtein(status1, status2, desc1, desc2))
	}

	log.Println("Building vantage point tree.")
	now := time.Now()
	tree := vptree.New(lvnst, objSlice)
	log.Printf("Done building vantage point tree after %s.", time.Since(now))

	log.Printf("Searching %d nearest neighbours to %s.\n", neighbours, rootrelay)
	now = time.Now()
	similarRelays, distances := tree.Search(targetRelay, neighbours+1)
	log.Printf("Found relays after looking for %s.", time.Since(now))

	targetStatus := targetRelay.(*tor.RouterStatus)
	targetDesc, _ := tor.LoadDescriptorFromDigest(params.DescriptorDir, targetStatus.Digest, targetStatus.Publication)
	// We skip the most similar relay because it's targetRelay.
	for i := 1; i < len(similarRelays); i++ {

		similarRelay := similarRelays[i].(*tor.RouterStatus)
		similarDesc, _ := tor.LoadDescriptorFromDigest(params.DescriptorDir, similarRelay.Digest, similarRelay.Publication)

		foundNeighbours[similarRelay.Fingerprint] = true

		_, comparedBlurb := LevenshteinVerbose(similarRelay, targetStatus, similarDesc, targetDesc)
		fmt.Println(comparedBlurb)

		fmt.Printf("Dist(%s, %s) = %.0f, <https://atlas.torproject.org/#details/%s>\n\n",
			targetRelay.GetFingerprint()[:8],
			similarRelay.GetFingerprint()[:8],
			distances[i],
			similarRelay.GetFingerprint())
	}

	return foundNeighbours, nil
}

// FindNearestNeighbours attempts to find the n nearest neighbours for the
// given reference relay.
func FindNearestNeighbours(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	for objects := range channel {
		VantagePointTreeSearch(objects, params)
	}
}
