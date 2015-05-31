// Computes similarity between router descriptors.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	tor "git.torproject.org/user/phw/zoossh.git"
	levenshtein "github.com/arbovm/levenshtein"
)

// hasDefaultExitPolicy returns true if the given descriptor's reject policy is
// the default reject policy.
func hasDefaultExitPolicy(desc *tor.RouterDescriptor) bool {

	defaultReject1 := "0.0.0.0/8:* 169.254.0.0/16:* 127.0.0.0/8:* " +
		"192.168.0.0/16:* 10.0.0.0/8:* 172.16.0.0/12:* "
	defaultReject2 := ":* *:25 *:119 *:135-139 *:445 *:563 *:1214 " +
		"*:4661-4666 *:6346-6429 *:6699 *:6881-6999"
	defaultReject := defaultReject1 + desc.Address.String() + defaultReject2

	return strings.TrimSpace(desc.RawReject) == defaultReject
}

// SybilCluster represents a cluster of potential Sybils.
type SybilCluster struct {
	SybilPairs []*DescriptorSimilarity
}

// DescriptorSimilarity is a heterogeneous vector representing the similarity
// between two router descriptors.
type DescriptorSimilarity struct {
	desc1 *tor.RouterDescriptor
	desc2 *tor.RouterDescriptor

	UptimeDiff      uint64
	BandwidthDiff   uint64
	ORPortDiff      uint16
	SharedFprPrefix uint32
	LevenshteinDist int
	SimilarityScore int

	SameFamily   bool
	SameAddress  bool
	SameContact  bool
	SameVersion  bool
	HaveDirPort  bool
	SamePolicy   bool
	SamePlatform bool

	StringSummary string
}

// genStringSimilarity generates and stores a human-readable string
// representation of the similarity between two relay descriptors.
func (s *DescriptorSimilarity) genStringSimilarity() {

	var contact, version, bandwidth, sharedFpr, family, policy, uptime, orport, platform string
	var similarities int

	if s.SameFamily {
		family = ", but same family"
	}

	if s.SamePlatform {
		similarities++
		platform = fmt.Sprintf("Same platform: %s\n", s.desc1.OperatingSystem)
	}

	if s.SameContact {
		similarities++
		contact = fmt.Sprintf("Same contact: %s\n", s.desc1.Contact)
	}

	if s.SameVersion {
		similarities++
		version = fmt.Sprintf("Same version: %s\n", s.desc1.TorVersion)
	}

	if s.BandwidthDiff == 0 {
		similarities++
		// The default bandwidth rate is 1 GiB/s, i.e., 1024^3 Bps.
		if s.desc1.BandwidthAvg == 1073741824 {
			bandwidth = fmt.Sprintln("Default 1 GiB/s bandwidth")
		} else {
			bandwidth = fmt.Sprintf("Same bandwidth: %d\n", s.desc1.BandwidthAvg)
		}
	}

	if s.SharedFprPrefix >= 2 {
		similarities++
		sharedFpr = fmt.Sprintf("First %d hex digits of fingerprint: %s\n",
			s.SharedFprPrefix, s.desc1.Fingerprint[:s.SharedFprPrefix])
	}

	if s.SamePolicy {
		similarities++
		policy = fmt.Sprintf("Same exit policy: %s\n", s.desc1.RawReject)
	}

	if s.UptimeDiff < (60 * 60 * 3) {
		similarities++
		uptime = fmt.Sprintf("Uptime diff: %d sec\n", s.UptimeDiff)
	}

	if (s.ORPortDiff < 10) && (s.desc1.ORPort != 9001) {
		similarities++
		orport = fmt.Sprintf("ORPort similar: desc1=%d, desc2=%d\n",
			s.desc1.ORPort, s.desc2.ORPort)
	}

	s.SimilarityScore = similarities
	s.StringSummary = fmt.Sprintf("%d similarities%s:\n"+
		"%s%s%s%s%s%s%s%s",
		similarities, family,
		sharedFpr,
		contact,
		version,
		policy,
		uptime,
		orport,
		bandwidth,
		platform)
}

// String implements the Stringer interface for pretty printing.  The output is
// meant to be human-readable and easy to grep(1).
func (s *DescriptorSimilarity) String() string {

	return s.StringSummary
}

// CalcDescSimilarity determines the similarity between the two given relay
// descriptors.  The similarity is a vector of numbers, which is returned.
func CalcDescSimilarity(desc1, desc2 *tor.RouterDescriptor) *DescriptorSimilarity {

	similarity := new(DescriptorSimilarity)

	similarity.desc1 = desc1
	similarity.desc2 = desc2

	similarity.UptimeDiff = MaxUInt64(desc1.Uptime, desc2.Uptime) -
		MinUInt64(desc1.Uptime, desc2.Uptime)
	similarity.BandwidthDiff = MaxUInt64(desc1.BandwidthAvg, desc2.BandwidthAvg) -
		MinUInt64(desc1.BandwidthAvg, desc2.BandwidthAvg)
	similarity.ORPortDiff = MaxUInt16(desc1.ORPort, desc2.ORPort) -
		MinUInt16(desc1.ORPort, desc2.ORPort)

	// We compare hex-encoded fingerprints, so we have a granularity of four
	// bits.  For example, the following two fingerprints have a shared prefix
	// of five:
	//   2C23B 21BEA DFB95 6247F  6DA97 36A61 EDCE9 48413
	//   2C23B 41049 6F573 A616B  FF37B C12A2 B39F2 DBE5E
	//   ^^^^^
	similarity.SharedFprPrefix = 0
	for i := 0; i < 40; i++ {
		if desc1.Fingerprint[i] != desc2.Fingerprint[i] {
			break
		}
		similarity.SharedFprPrefix++
	}

	// The Levenshtein distance gives us an approximation of how similar two
	// nicknames are.
	similarity.LevenshteinDist = levenshtein.Distance(desc1.Nickname, desc2.Nickname)

	similarity.SameFamily = desc1.HasFamily(desc2.Fingerprint) && desc2.HasFamily(desc1.Fingerprint)
	similarity.SameAddress = desc1.Address.Equal(desc2.Address)
	similarity.SameContact = (desc1.Contact == desc2.Contact) && desc1.Contact != ""
	similarity.SameVersion = (desc1.TorVersion == desc2.TorVersion)
	similarity.HaveDirPort = (desc1.DirPort != 0) && (desc2.DirPort != 0)
	similarity.SamePlatform = desc1.OperatingSystem == desc2.OperatingSystem

	// We don't care about the default or the universal reject policy.
	if !hasDefaultExitPolicy(desc1) && strings.TrimSpace(desc1.RawReject) != "*:*" {
		similarity.SamePolicy = desc1.RawReject == desc2.RawReject
	}

	similarity.genStringSimilarity()

	return similarity
}

// genSimilarityMatrix computes pairwise similarities for all given relay
// descriptors.  If "visualise" is set to false, all (n^2)/2 similarities are
// written to stdout in human-readable output.  If "visualise" is true, the
// output is Dot code, that can be turned into a diagram for visual inspection.
func genSimilarityMatrix(descs *tor.RouterDescriptors, threshold int, visualise bool) {

	// Turn the map keys (i.e., the relays' fingerprints) into a list.
	size := len(descs.RouterDescriptors)
	fprs := make([]string, size)

	i := 0
	for fpr, _ := range descs.RouterDescriptors {
		fprs[i] = fpr
		i++
	}

	log.Printf("Now processing %d router descriptors.\n", size)

	cluster := SybilCluster{}

	// Compute similarity matrix.
	count := 0
	for i := 0; i < size; i++ {

		fpr1 := fprs[i]
		for j := i + 1; j < size; j++ {

			count++
			fpr2 := fprs[j]
			desc1, _ := descs.Get(fpr1)
			desc2, _ := descs.Get(fpr2)

			similarity := CalcDescSimilarity(desc1, desc2)
			if similarity.SimilarityScore < threshold {
				continue
			}

			cluster.SybilPairs = append(cluster.SybilPairs, similarity)

			// Write similarities between two descriptors as human-readable,
			// easy-to-grep output to stdout.
			if !visualise {
				fmt.Printf("<https://atlas.torproject.org/#details/%s> (%s)\n",
					similarity.desc1.Fingerprint, similarity.desc1.Nickname)
				fmt.Printf("<https://atlas.torproject.org/#details/%s> (%s)\n",
					similarity.desc2.Fingerprint, similarity.desc2.Nickname)
				fmt.Println(similarity)
			}
		}
	}

	log.Printf("Computed %d pairwise similarities, %d are part of output.\n",
		count, len(cluster.SybilPairs))

	if visualise {
		GenerateDOTGraph(&cluster)
	}
}

// extractObjects attempts to parse the given, unknown file and returns a
// collection of objects.  It's up to the caller to convert the returned
// interface type to something more useful.
func extractObjects(path string, info os.FileInfo) (tor.ObjectSet, error) {

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("File \"%s\" does not exist.", path)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("\"%s\" is a directory.", path)
	}

	objects, err := tor.ParseUnknownFile(path)
	if err != nil {
		return nil, err
	}

	return objects, nil
}

// accumulateDescriptors returns a walking function that accumulates the router
// descriptors of all encountered files.
func accumulateDescriptors(descs *tor.RouterDescriptors) filepath.WalkFunc {

	return func(path string, info os.FileInfo, err error) error {

		if err != nil {
			log.Println(err)
			return nil
		}

		objects, err := extractObjects(path, info)
		if err != nil {
			log.Println(err)
			return nil
		}

		switch v := objects.(type) {
		case *tor.RouterDescriptors:
			for fpr, getVal := range v.RouterDescriptors {
				descs.Set(fpr, getVal())
			}
		default:
			log.Printf("File format of \"%s\" not yet supported.\n", path)
		}

		return nil
	}
}

// SimilarityMatrix walks the given file or directory and computes pairwise
// relay similarities.  If the cumulative argument is set to true, the content
// of all files is accumulated rather than analysed independently.
func SimilarityMatrix(params *CmdLineParams) {

	if params.Cumulative {
		log.Println("Processing files cumulatively.")
		descs := tor.NewRouterDescriptors()
		filepath.Walk(params.InputData, accumulateDescriptors(descs))
		genSimilarityMatrix(descs, params.Threshold, params.Visualise)
	} else {
		log.Println("Processing files independently.")

		processDescs := func(path string, info os.FileInfo, err error) error {
			objects, err := extractObjects(path, info)
			if err != nil {
				log.Println(err)
				return nil
			}

			switch objs := objects.(type) {
			case *tor.RouterDescriptors:
				genSimilarityMatrix(objs, params.Threshold, params.Visualise)
			default:
				log.Printf("File format of \"%s\" not yet supported.\n", path)
			}

			return nil
		}

		filepath.Walk(params.InputData, processDescs)
	}
}

// FindNearestNeighbours attempts to find the nearest neighbours for the given
// relay.
func FindNearestNeighbours(params *CmdLineParams) {

	objects, err := tor.ParseUnknownFile(params.InputData)
	if err != nil {
		log.Fatalln(err)
		return
	}

	VantagePointTreeSearch(objects, params.ReferenceRelay, params.Neighbours)
}
