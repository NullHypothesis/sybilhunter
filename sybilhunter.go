// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
)

const (
	version    = "2015.01.a"
	timeLayout = "2006-01-02_15:04:05"
)

// Files for manual analysis are written to this directory.
var outputDir string

func main() {

	var differenceThreshold int

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	archive := flag.String("archive", "", "Analyse a directory containing archived Tor network statuses.")
	fingerprints := flag.String("fingerprint", "", "Analyse relay fingerprints in the given file or directory.")
	flag.IntVar(&differenceThreshold, "threshold", 50, "Dump consensus when new fingerprints exceed given threshold.")
	flag.StringVar(&outputDir, "output", "", "Directory where analysis results are written to.")
	reverse := flag.Bool("reverse", false, "Parse given archive in reverse order.")

	flag.Parse()

	if (*archive == "") && !(*showVersion) && (*fingerprints == "") {
		log.Fatalln("No commands given.  Supported commands: -archive, -version, -fingerprint.")
	}

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if *fingerprints != "" {
		// Parse all given files and determine statistics.
		filepath.Walk(*fingerprints, AnalyseFingerprints)
		vs := ValueSorter{
			keys: make([]string, 0),
			vals: make([]int, 0),
		}

		// Use ValueSorter to sort by IP addresses with most unique fingerprints.
		for ipAddr, fprList := range FprAnalysis {
			vs.keys = append(vs.keys, ipAddr)
			vs.vals = append(vs.vals, len(fprList))
		}
		sort.Sort(vs)

		for i, val := range vs.keys {
			fmt.Printf("%s (%d unique fingerprints)\n", val, vs.vals[i])
			for fingerprint, count := range FprAnalysis[val] {
				fmt.Printf("\t%s (seen %d times)\n", fingerprint, count)
			}
		}
	}

	if *archive != "" {

		// First, collect all file names in the given directory in lexical
		// order.  We are then able to also walk these files in reverse lexical
		// order which is not supported by Go's Walk API.
		var fileNames []string
		filepath.Walk(*archive, collectFiles(&fileNames))
		fileNamesLen := len(fileNames)

		archiveParser := getArchiveParser(differenceThreshold)
		if *reverse {
			for i := fileNamesLen - 1; i >= 0; i-- {
				archiveParser(fileNames[i])
			}
		} else {
			for i := 0; i < fileNamesLen; i++ {
				archiveParser(fileNames[i])
			}
		}
	}
}
