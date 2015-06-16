// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
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

	// Callbacks holds a slice of analysis functions that are called for parsed
	// data objects.
	Callbacks []AnalysisCallback
}

// AnalysisCallback is a callback function that analyses the given object set.
type AnalysisCallback func(chan tor.ObjectSet, *CmdLineParams, *sync.WaitGroup)

func main() {

	var threshold int

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	printFiles := flag.Bool("print", false, "Print the content of all files in the given file or directory.")
	fingerprints := flag.Bool("fingerprint", false, "Analyse relay fingerprints in the given file or directory.")
	matrix := flag.Bool("matrix", false, "Calculate O(n^2) similarity matrix for all objects in the given file or directory.")
	cumulative := flag.Bool("cumulative", false, "Accumulate all files in a directory rather than process them independently.")
	visualise := flag.Bool("visualise", false, "Write DOT code to stdout, that can then be turned into a diagram using Graphviz.")
	nofamily := flag.Bool("nofamily", true, "Don't interpret MyFamily relationships as Sybils.")
	churn := flag.Bool("churn", false, "Determine churn rate of given set of consensuses.  Requires -threshold parameter.")

	neighbours := flag.Int("neighbours", 0, "Find n nearest neighbours.")
	flag.IntVar(&threshold, "threshold", -1, "Analysis-specific threshold.")

	data := flag.String("data", "", "File or directory to analyse.  It must contain network statuses or relay descriptors.")
	referenceRelay := flag.String("referencerelay", "", "Relay that's used as reference for nearest neighbour search.")
	flag.StringVar(&outputDir, "output", "", "Directory where analysis results are written to.")

	flag.Parse()

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	// Store and pass command line arguments to analysis methods.
	params := CmdLineParams{threshold, *neighbours, *visualise, *cumulative,
		*nofamily, *data, outputDir, *referenceRelay, []AnalysisCallback{}}

	if *data == "" {
		log.Fatalln("No file or directory given.  Please use the -data switch.")
	}

	if *matrix {
		if threshold == -1 {
			log.Println("You might want to use -threshold to only consider similarities above or equal to the given threshold.")
		}
		params.Callbacks = append(params.Callbacks, SimilarityMatrix)
	}

	if *fingerprints {
		params.Callbacks = append(params.Callbacks, AnalyseFingerprints)
	}

	if *printFiles {
		params.Callbacks = append(params.Callbacks, PrettyPrint)
	}

	if *neighbours != 0 {
		if *referenceRelay == "" {
			log.Fatalln("No reference relay given.  Please use the -referencerelay switch.")
		}
		params.Callbacks = append(params.Callbacks, FindNearestNeighbours)
	}

	if *churn {
		params.Callbacks = append(params.Callbacks, AnalyseChurn)
	}

	if len(params.Callbacks) == 0 {
		log.Fatalln("No command given.  Please use -print, -fingerprint, -matrix, -neighbours, or -churn.")
	}

	if err := ParseFiles(&params); err != nil {
		log.Fatal(err)
	}

}

// GatherObjects returns a WalkFunc that gathers data objects from a file or
// directory.  If the given object set pointer is not nil, it is used to
// accumulate objects.  If the given channels are not nil, GatherObjects sends
// the gathered data objects over the channels instead of accumulating them.
func GatherObjects(objs *tor.ObjectSet, channels []chan tor.ObjectSet) filepath.WalkFunc {

	return func(path string, info os.FileInfo, err error) error {

		if _, err := os.Stat(path); err != nil {
			log.Printf("File \"%s\" does not exist.\n", path)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		log.Printf("Trying to parse file \"%s\".", path)
		objects, err := tor.ParseUnknownFile(path)
		if err != nil {
			log.Println(err)
			return nil
		}

		if channels != nil {
			// Processing independently.
			for _, channel := range channels {
				if objects != nil {
					channel <- objects
				}
			}
		} else {
			// Processing cumulatively.
			if *objs == nil {
				*objs = objects
			} else {
				(*objs).Merge(objects)
			}
		}

		return nil
	}
}

// ParseFiles parses the given directory or files and passes the parsed data to
// the given analysis functions.  ParseFiles then waits for all these functions
// to finish processing.
func ParseFiles(params *CmdLineParams) error {

	var objs tor.ObjectSet
	var channels []chan tor.ObjectSet
	var group sync.WaitGroup
	group.Add(len(params.Callbacks))

	// Create a channel for and invoke all callback functions.
	for _, analysisFunc := range params.Callbacks {
		channel := make(chan tor.ObjectSet)
		channels = append(channels, channel)

		go analysisFunc(channel, params, &group)
	}

	if params.Cumulative {
		log.Printf("Processing \"%s\" cumulatively.\n", params.InputData)
		filepath.Walk(params.InputData, GatherObjects(&objs, nil))

		if objs == nil {
			return errors.New("Gathered object set empty.  Are we parsing the right files?")
		}

		// Send accumulated object set to all callback functions.
		for _, channel := range channels {
			channel <- objs
		}
	} else {
		log.Printf("Processing \"%s\" independently.\n", params.InputData)
		filepath.Walk(params.InputData, GatherObjects(nil, channels))
	}

	// Close processing channels and wait for goroutines to finish.
	for _, channel := range channels {
		close(channel)
	}
	group.Wait()

	return nil
}
