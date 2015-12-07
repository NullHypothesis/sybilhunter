// Distance metrics for Tor objects.
package main

import (
	"fmt"

	tor "git.torproject.org/user/phw/zoossh.git"
	levenshtein "github.com/arbovm/levenshtein"
	cluster "github.com/NullHypothesis/mlgo/cluster"
	statistics "github.com/mcgrew/gostats"
)

// Distance quantifies the distance between the two given "Tor objects" (e.g.,
// router statuses or descriptors) as 32-bit float.
type Distance func(obj1, obj2 tor.Object) float32

// Levenshtein determines the Levenshtein distance, a string metric, between
// the two given objects.  Depending on whether we are dealing with router
// statuses or descriptors, we generate different strings.  In contrast to
// LevenshteinVerbose, this function only returns the distance.
func Levenshtein(obj1, obj2 tor.Object) float32 {

	distance, _ := LevenshteinVerbose(obj1, obj2)
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
// between the two given Tor objects.  Depending on whether we are dealing with
// router statuses or descriptors, we compare different strings.
func LevenshteinVerbose(obj1, obj2 tor.Object) (float32, string) {

	var str1, str2 string

	switch x := obj1.(type) {

	// dir-spec.txt says that nicknames can have a maximum of 19 characters.

	case *tor.RouterStatus:
		status1 := x
		status2 := obj2.(*tor.RouterStatus)

		str1 = fmt.Sprintf("%19s%5d%5d%s%12s%20s%12d%s",
			status1.Nickname,
			status1.ORPort,
			status1.DirPort,
			status1.Publication,
			RouterFlagsToString(&status1.Flags),
			status1.TorVersion,
			status1.Bandwidth,
			status1.PortList)

		str2 = fmt.Sprintf("%19s%5d%5d%s%12s%20s%12d%s",
			status2.Nickname,
			status2.ORPort,
			status2.DirPort,
			status2.Publication,
			RouterFlagsToString(&status2.Flags),
			status2.TorVersion,
			status2.Bandwidth,
			status2.PortList)

	case *tor.RouterDescriptor:
		desc1 := x
		desc2 := obj2.(*tor.RouterDescriptor)

		str1 = fmt.Sprintf("%19s%5d%5d%s",
			desc1.Nickname,
			desc1.ORPort,
			desc1.DirPort,
			desc1.Published)

		str2 = fmt.Sprintf("%19s%5d%5d%s",
			desc2.Nickname,
			desc2.ORPort,
			desc2.DirPort,
			desc2.Published)
	}

	verbose := fmt.Sprintf("%s: %s\n%s: %s",
		obj1.GetFingerprint()[:8], str1,
		obj2.GetFingerprint()[:8], str2)

	return float32(levenshtein.Distance(str1, str2)), verbose
}
