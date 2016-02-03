// Distance metrics for Tor objects.
package main

import (
	"fmt"

	tor "git.torproject.org/user/phw/zoossh.git"
	cluster "github.com/NullHypothesis/mlgo/cluster"
	levenshtein "github.com/arbovm/levenshtein"
	statistics "github.com/mcgrew/gostats"
)

// RelayDistances contains a slice for relays and their corresponding distance
// to another relay.
type RelayDistances struct {
	Distances []float32
	Relays    []*tor.RouterStatus
}

// Len implements the Sorter interface.
func (rd RelayDistances) Len() int {
	return len(rd.Distances)
}

// Swap implements the Sorter interface.
func (rd RelayDistances) Swap(i, j int) {
	rd.Distances[i], rd.Distances[j] = rd.Distances[j], rd.Distances[i]
	rd.Relays[i], rd.Relays[j] = rd.Relays[j], rd.Relays[i]
}

// Less implements the Sorter interface.
func (rd RelayDistances) Less(i, j int) bool {
	return rd.Distances[i] < rd.Distances[j]
}

// Add adds a new relay with its corresponding distance to the struct.
func (rd *RelayDistances) Add(relay *tor.RouterStatus, dist float32) {

	rd.Distances = append(rd.Distances, dist)
	rd.Relays = append(rd.Relays, relay)
}

// Distance quantifies the distance between the two given "Tor objects" (e.g.,
// router statuses or descriptors) as 32-bit float.
type Distance func(obj1, obj2 tor.Object) float32

// Levenshtein determines the Levenshtein distance, a string metric, between
// the given router statuses and descriptors.  In contrast to
// LevenshteinVerbose, this function only returns the distance.
func Levenshtein(stat1, stat2 *tor.RouterStatus, desc1, desc2 *tor.RouterDescriptor) float32 {

	distance, _ := LevenshteinVerbose(stat1, stat2, desc1, desc2)
	return distance
}

// PearsonWrapper is a wrapper around PearsonCorrelation.
func PearsonWrapper(a, b cluster.Vector) float64 {
	return 1 - PearsonCorrelation(a, b)
}

// PearsonCorrelation determines the Pearson correlation coefficient.
func PearsonCorrelation(a, b []float64) float64 {

	return statistics.PearsonCorrelation(a, b)
}

// LevenshteinVerbose determines the Levenshtein distance, a string metric,
// between the given router statuses and descriptors.
func LevenshteinVerbose(status1, status2 *tor.RouterStatus, desc1, desc2 *tor.RouterDescriptor) (float32, string) {

	var str1, str2 string

	if desc1 == nil {
		desc1 = new(tor.RouterDescriptor)
	}
	if desc2 == nil {
		desc2 = new(tor.RouterDescriptor)
	}

	str1 = fmt.Sprintf("%s%s%d%d%s%s%s%d%d%s%s%d%s",
		status1.Nickname,
		status1.Address,
		status1.ORPort,
		status1.DirPort,
		RouterFlagsToString(&status1.Flags),
		status1.TorVersion,
		status1.PortList,
		desc1.BandwidthAvg,
		desc1.BandwidthBurst,
		desc1.OperatingSystem,
		desc1.Published,
		desc1.Uptime,
		desc1.Contact)

	str2 = fmt.Sprintf("%s%s%d%d%s%s%s%d%d%s%s%d%s",
		status2.Nickname,
		status2.Address,
		status2.ORPort,
		status2.DirPort,
		RouterFlagsToString(&status2.Flags),
		status2.TorVersion,
		status2.PortList,
		desc2.BandwidthAvg,
		desc2.BandwidthBurst,
		desc2.OperatingSystem,
		desc2.Published,
		desc2.Uptime,
		desc2.Contact)

	verbose := fmt.Sprintf("%s: %s\n%s: %s",
		status1.Fingerprint[:8], str1,
		status2.Fingerprint[:8], str2)

	return float32(levenshtein.Distance(str1, str2)), verbose
}
