// Analyse churn rate of a set of consensuses.
package main

import (
	"fmt"
	"log"
	"math"
	"reflect"
	"sync"
	"time"

	tor "git.torproject.org/user/phw/zoossh.git"
)

const (
	Appeared    = true
	Disappeared = false
)

// RelayFlags holds the relay flags that will be analysed.
var RelayFlags = []string{
	"Authority",
	"BadExit",
	"Exit",
	"Fast",
	"Guard",
	"HSDir",
	"Named",
	"Running",
	"Stable",
	"Unnamed",
	"V2Dir",
	"Valid"}

// Churn holds two churn values, for relays that went online and relays that
// went offline.
type Churn struct {
	Online  float64
	Offline float64
}

// PerFlagMovAvg maps a relay flag, e.g., "Guard", to a moving average struct.
type PerFlagMovAvg map[string]*MovingAverage

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
		total.Online += ma.Window[i].Online
		total.Offline += ma.Window[i].Offline
	}
	total.Online /= float64(ma.WindowSize)
	total.Offline /= float64(ma.WindowSize)

	return total
}

// AddValue adds a churn value to the moving average window.
func (ma *MovingAverage) AddValue(val Churn) {

	if ma.WindowFill < ma.WindowSize {
		ma.WindowFill++
	}
	ma.Window[ma.WindowIndex].Online = val.Online
	ma.Window[ma.WindowIndex].Offline = val.Offline
	ma.WindowIndex = (ma.WindowIndex + 1) % ma.WindowSize
}

// IsWindowFull returns true if the moving average's window is full.
func (ma *MovingAverage) IsWindowFull() bool {

	return ma.WindowFill == ma.WindowSize
}

// dumpChurnRelays dumps the given relays to stderr for manual analysis.
func dumpChurnRelays(relays *tor.Consensus, prefix string, date time.Time) {

	// Sort relays by nickname.
	nickname := func(relay1, relay2 tor.GetStatus) bool {
		return relay1().Nickname < relay2().Nickname
	}

	sliceRelays := relays.ToSlice()
	By(nickname).Sort(sliceRelays)

	for _, getStatus := range sliceRelays {
		status := getStatus()
		log.Printf("%s <https://atlas.torproject.org/#details/%s> %s\n",
			prefix, status.Fingerprint, status.Nickname)
	}
}

// determineChurn determines and returns the churn rate of the two given
// subsequent consensuses.  For the churn rate, we adapt the formula shown in
// Section 2.1 of: <http://www.cs.berkeley.edu/~istoica/papers/2006/churn.pdf>.
func determineChurn(prevConsensus, newConsensus *tor.Consensus) Churn {

	goneRelays := prevConsensus.Subtract(newConsensus)
	newRelays := newConsensus.Subtract(prevConsensus)

	max := math.Max(float64(prevConsensus.Length()), float64(newConsensus.Length()))
	newChurn := (float64(newRelays.Length()) / max)
	goneChurn := (float64(goneRelays.Length()) / max)

	return Churn{newChurn, goneChurn}
}

// FilterConsensusByFlag filters the given consensus so that only relays with
// the given flag remain.  The resulting consensus is returned.
func FilterConsensusByFlag(consensus *tor.Consensus, flag string) *tor.Consensus {

	filteredConsensus := tor.NewConsensus()

	for fingerprint, getStatus := range consensus.RouterStatuses {
		status := getStatus()

		s := reflect.ValueOf(&status.Flags).Elem()
		flagSet := s.FieldByName(flag).Interface()
		// Check if relay has the flag we are looking for.
		if flagSet == true {
			filteredConsensus.Set(fingerprint, status)
		}
	}

	return filteredConsensus
}

// DeterminePerFlagChurn determines the churn rate between two subsequent
// consensuses for all relays with a given flag.  For example, for all relays
// with the "Guard" flag, we get a churn value for relays that went online and a
// churn value for relays that went offline.  A set of relays is dumped to
// stderr once a churn value exceeds the given threshold.
func DeterminePerFlagChurn(prevConsensus, newConsensus *tor.Consensus, movAvg PerFlagMovAvg, params *CmdLineParams) {

	var line string

	for _, flag := range RelayFlags {

		prevFiltered := FilterConsensusByFlag(prevConsensus, flag)
		newFiltered := FilterConsensusByFlag(newConsensus, flag)
		churn := determineChurn(prevFiltered, newFiltered)

		// Determine moving average for captured churn values.
		movAvg[flag].AddValue(churn)
		churn = movAvg[flag].CalcAvg()
		if !movAvg[flag].IsWindowFull() {
			continue
		}

		if churn.Online >= params.Threshold {
			dumpChurnRelays(newFiltered.Subtract(prevFiltered), "+"+flag, newConsensus.ValidAfter)
		}
		if churn.Offline >= params.Threshold {
			dumpChurnRelays(prevFiltered.Subtract(newFiltered), "-"+flag, newConsensus.ValidAfter)
		}

		if params.CSVFormat == longCSVFormat {
			fmt.Printf("%s", newConsensus.ValidAfter.Format("2006-01-02T15:04:05Z"))
			for _, noFlag := range RelayFlags {
				if noFlag != flag {
					fmt.Printf(",NA")
				} else {
					fmt.Printf(",T")
				}
			}
			fmt.Printf(",%.5f,%.5f\n", churn.Online, churn.Offline)
		} else {
			if line == "" {
				line += fmt.Sprintf("%s", newConsensus.ValidAfter.Format("2006-01-02T15:04:05Z"))
			}
			line += fmt.Sprintf(",%.5f,%.5f", churn.Online, churn.Offline)
		}
	}

	if line != "" {
		fmt.Println(line)
	}
}

// AnalyseChurn determines the churn rates of a set of consecutive consensuses.
// If the churn rate exceeds the given threshold, all new and disappeared
// relays are dumped to stderr.
func AnalyseChurn(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	var newConsensus, prevConsensus *tor.Consensus

	if params.WindowSize <= 0 {
		log.Printf("Window size set to %d, but cannot be smaller than 1.  Setting it to 1.", params.WindowSize)
		params.WindowSize = 1
	}

	log.Printf("Threshold for churn analysis is %.5f.\n", params.Threshold)

	// Print CSV header, either in long or wide format.
	fmt.Print("Date")
	for _, flag := range RelayFlags {
		if params.CSVFormat == longCSVFormat {
			fmt.Printf(",%s", flag)
		} else {
			fmt.Printf(",New%s,Gone%s", flag, flag)
		}
	}
	if params.CSVFormat == longCSVFormat {
		fmt.Print(",NewChurn,GoneChurn")
	}
	fmt.Println()

	movAvg := make(PerFlagMovAvg)
	for _, flag := range RelayFlags {
		movAvg[flag] = NewMovingAverage(params.WindowSize)
	}

	// Every loop iteration processes one consensus.  We compare consensus t
	// to consensus t - 1.
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

		DeterminePerFlagChurn(prevConsensus, newConsensus, movAvg, params)

		prevConsensus = newConsensus
	}
}
