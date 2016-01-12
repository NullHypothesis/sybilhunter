// Analyse churn rate of a set of consensuses.
package main

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// Churn represents a churn value.
type Churn float64

// MovingAverage represents a simple moving average.
type MovingAverage struct {
	WindowIndex int
	WindowSize  int
	WindowFill  int
	Window      []Churn
}

// NewMovingAverage allocates and returns a new moving average struct.
func NewMovingAverage(windowSize int) *MovingAverage {

	return &MovingAverage{WindowIndex: 0, WindowSize: windowSize, Window: make([]Churn, windowSize)}
}

// CalcAvg determines and returns the mean of the moving average window.
func (ma *MovingAverage) CalcAvg() Churn {

	var total Churn
	for i := 0; i < ma.WindowSize; i++ {
		total += ma.Window[i]
	}
	return total / Churn(ma.WindowSize)
}

// AddValue returns a churn value to the moving average window.
func (ma *MovingAverage) AddValue(val Churn) {

	if ma.WindowFill < ma.WindowSize {
		ma.WindowFill++
	}
	ma.Window[ma.WindowIndex] = val
	ma.WindowIndex = (ma.WindowIndex + 1) % ma.WindowSize
}

// IsWindowFull returns true if the moving average's window is full.
func (ma *MovingAverage) IsWindowFull() bool {

	return ma.WindowFill == ma.WindowSize
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
		log.Printf("- <https://atlas.torproject.org/#details/%s> %s\n",
			getStatus().Fingerprint, getStatus().Nickname)
	}
	for _, getStatus := range fresh {
		log.Printf("+ <https://atlas.torproject.org/#details/%s> %s\n",
			getStatus().Fingerprint, getStatus().Nickname)
	}
}

// determineChurn determines and returns the churn rate of the two given
// subsequent consensuses.  For the churn rate, we adapt the formula shown in
// Section 2.1 of: <http://www.cs.berkeley.edu/~istoica/papers/2006/churn.pdf>.
func determineChurn(prevConsensus, newConsensus *tor.Consensus) (Churn, Churn) {

	goneRelays := prevConsensus.Subtract(newConsensus)
	newRelays := newConsensus.Subtract(prevConsensus)

	max := math.Max(float64(prevConsensus.Length()), float64(newConsensus.Length()))
	newChurn := (float64(newRelays.Length()) / max)
	goneChurn := (float64(goneRelays.Length()) / max)

	return Churn(newChurn), Churn(goneChurn)
}

// AnalyseChurn determines the churn rates of a set of consecutive consensuses.
// If the churn rate exceeds the given threshold, all new and disappeared
// relays are dumped to stdout.
func AnalyseChurn(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	var newConsensus, prevConsensus *tor.Consensus

	log.Printf("Threshold for churn analysis is %.5f.\n", params.Threshold)
	fmt.Println("date,newchurn,gonechurn,avgnewchurn,avggonechurn")

	movingAvgNew := NewMovingAverage(params.WindowSize)
	movingAvgGone := NewMovingAverage(params.WindowSize)

	// Every loop iteration processes one consensus.  We compare consensus t
	// with consensus t - 1.
	for objects := range channel {

		switch obj := objects.(type) {
		case *tor.Consensus:
			newConsensus = obj
		default:
			log.Fatalln("Only router status files are supported for churn analysis.")
		}

		if prevConsensus == nil {
			prevConsensus = newConsensus
			continue
		}

		// Are we missing consensuses?
		if prevConsensus.ValidAfter.Add(time.Hour) != newConsensus.ValidAfter {
			log.Printf("Missing consensuses between %s and %s.\n",
				prevConsensus.ValidAfter.Format(time.RFC3339),
				newConsensus.ValidAfter.Format(time.RFC3339))
			prevConsensus = newConsensus
			continue
		}

		newChurn, goneChurn := determineChurn(prevConsensus, newConsensus)

		// Update moving averages.
		movingAvgNew.AddValue(newChurn)
		movingAvgGone.AddValue(goneChurn)

		newAvg := movingAvgNew.CalcAvg()
		goneAvg := movingAvgGone.CalcAvg()

		// Set averaged values to -1 if we our window isn't full yet.
		if !movingAvgNew.IsWindowFull() {
			newAvg = -1
			goneAvg = -1
		}
		timeStr := newConsensus.ValidAfter.Format("2006-01-02T15:04:05Z")
		fmt.Printf("%s,%.5f,%.5f,%.5f,%.5f\n", timeStr, newChurn, goneChurn, newAvg, goneAvg)

		if (newChurn >= Churn(params.Threshold)) || (goneChurn >= Churn(params.Threshold)) {
			goneRelays := prevConsensus.Subtract(newConsensus)
			newRelays := newConsensus.Subtract(prevConsensus)
			dumpChurnRelays(goneRelays, newRelays)
		}

		prevConsensus = newConsensus
	}
}
