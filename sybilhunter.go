// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
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
	printFiles := flag.Bool("print", false, "Print the content of all files in the given file or directory.")
	fingerprints := flag.Bool("fingerprint", false, "Analyse relay fingerprints in the given file or directory.")
	similarity := flag.Bool("similarity", false, "Calculate pairwise similarities for all files in the given file or directory.")
	cumulative := flag.Bool("cumulative", false, "Accumulate all files rather than process them independently.")
	neighbours := flag.Int("neighbours", 0, "Find n nearest neighbours.")
	data := flag.String("data", "", "File or directory to analyse.  It must contain network statuses or relay descriptors.")
	rootrelay := flag.String("rootrelay", "", "Relay that's used for nearest neighbour search.")
	flag.IntVar(&differenceThreshold, "threshold", 50, "Dump consensus when new fingerprints exceed given threshold.")
	flag.StringVar(&outputDir, "output", "", "Directory where analysis results are written to.")

	flag.Parse()

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if *data == "" {
		log.Fatalln("No file or directory given.  Please use the -data switch.")
	}

	if *similarity {
		AnalyseSimilarities(*data, *cumulative)
		return
	}

	if *fingerprints {
		AnalyseFingerprints(*data)
		return
	}

	if *printFiles {
		PrettyPrint(*data)
		return
	}

	if *neighbours != 0 {
		if *rootrelay == "" {
			log.Fatalln("No root relay given.  Please use the -rootrelay switch.")
		}
		FindNearestNeighbours(*data, *rootrelay, *neighbours)
		return
	}

	log.Fatalln("No command given.  Please use -print, -fingerprint, -similarity, or -neighbours.")
}
