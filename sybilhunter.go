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

// CmdLineParams stores command line arguments.
type CmdLineParams struct {
	Threshold      int
	Neighbours     int
	Visualise      bool
	Cumulative     bool
	NoFamily       bool
	InputData      string
	OutputDir      string
	ReferenceRelay string
}

func main() {

	var threshold int

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	printFiles := flag.Bool("print", false, "Print the content of all files in the given file or directory.")
	fingerprints := flag.Bool("fingerprint", false, "Analyse relay fingerprints in the given file or directory.")
	matrix := flag.Bool("matrix", false, "Calculate O(n^2) similarity matrix for all files in the given file or directory.")
	cumulative := flag.Bool("cumulative", false, "Accumulate all files rather than process them independently.")
	visualise := flag.Bool("visualise", false, "Write Dot code to stdout, that can then be turned into a diagram using GraphViz.")
	nofamily := flag.Bool("nofamily", true, "Don't interpret MyFamily relationships as Sybils.")

	neighbours := flag.Int("neighbours", 0, "Find n nearest neighbours.")

	data := flag.String("data", "", "File or directory to analyse.  It must contain network statuses or relay descriptors.")
	referenceRelay := flag.String("referencerelay", "", "Relay that's used for nearest neighbour search.")

	flag.IntVar(&threshold, "threshold", -1, "Analysis-specific threshold.")
	flag.StringVar(&outputDir, "output", "", "Directory where analysis results are written to.")

	flag.Parse()

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	// Store and pass command line arguments to analysis methods.
	params := CmdLineParams{threshold, *neighbours, *visualise, *cumulative,
		*nofamily, *data, outputDir, *referenceRelay}

	if *data == "" {
		log.Fatalln("No file or directory given.  Please use the -data switch.")
	}

	if *matrix {
		if threshold == -1 {
			log.Println("You might want to use -threshold to only consider similarities above or equal to the given threshold.")
		}
		log.Println("Generating similarity matrix.")
		SimilarityMatrix(&params)
		return
	}

	if *fingerprints {
		log.Println("Analysing how often relays change their fingerprints.")
		AnalyseFingerprints(&params)
		return
	}

	if *printFiles {
		log.Println("Pretty-printing files.")
		PrettyPrint(&params)
		return
	}

	if *neighbours != 0 {
		if *referenceRelay == "" {
			log.Fatalln("No reference relay given.  Please use the -referencerelay switch.")
		}
		log.Printf("Finding nearest neighbours to %s.\n", *referenceRelay)
		FindNearestNeighbours(&params)
		return
	}

	log.Fatalln("No command given.  Please use -print, -fingerprint, -matrix, or -neighbours.")
}
