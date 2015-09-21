// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

const (
	toolName   = "sybilhunter"
	version    = "2015.01.a"
	timeLayout = "2006-01-02_15:04:05"
	configFile = ".sybilhunterrc"
)

// Files for manual analysis are written to this directory.
var outputDir string

// CmdLineParams stores command line arguments.
type CmdLineParams struct {
	Threshold      float64
	BwFraction     float64
	Neighbours     int
	Uptime         bool
	Contrib        bool
	Churn          bool
	PrintFiles     bool
	Fingerprints   bool
	Matrix         bool
	ShowVersion    bool
	Visualise      bool
	Cumulative     bool
	NoFamily       bool
	DescriptorDir  string
	ArchiveData    string
	InputData      string
	OutputDir      string
	ReferenceRelay string

	// Callbacks holds a slice of analysis functions that are called for parsed
	// data objects.
	Callbacks []AnalysisCallback
}

// AnalysisCallback is a callback function that analyses the given object set.
type AnalysisCallback func(chan tor.ObjectSet, *CmdLineParams, *sync.WaitGroup)

// ParseFlagSet parses the given arguments and returns a CmdLineParams struct.
// If the given CmdLineParams struct is not nil, its content is overwritten
// with the given arguments.
func ParseFlagSet(arguments []string, params *CmdLineParams) *CmdLineParams {

	if params == nil {
		params = new(CmdLineParams)
		params.BwFraction = -1
		params.Neighbours = -1
	}

	flags := flag.NewFlagSet(toolName, flag.ExitOnError)
	flags.Float64Var(&params.Threshold, "threshold", params.Threshold, "Analysis-specific threshold.")
	flags.Float64Var(&params.BwFraction, "bwfraction", params.BwFraction, "Print which relays amount to the given total bandwidth fraction.")
	flags.IntVar(&params.Neighbours, "neighbours", params.Neighbours, "Find n nearest neighbours.")
	flags.BoolVar(&params.Uptime, "uptime", params.Uptime, "Create relay uptime visualisation.  Use -input for output file name.")
	flags.BoolVar(&params.Contrib, "contrib", params.Contrib, "Determine the bandwidth contribution of relays in the given IP address blocks.")
	flags.BoolVar(&params.Churn, "churn", params.Churn, "Determine churn rate of given set of consensuses.  Requires -threshold parameter.")
	flags.BoolVar(&params.PrintFiles, "print", params.PrintFiles, "Print the content of all files in the given file or directory.")
	flags.BoolVar(&params.Fingerprints, "fingerprints", params.Fingerprints, "Analyse relay fingerprints in the given file or directory.")
	flags.BoolVar(&params.Matrix, "matrix", params.Matrix, "Calculate O(n^2) similarity matrix for all objects in the given file or directory.")
	flags.BoolVar(&params.ShowVersion, "version", params.ShowVersion, "Show version and exit.")
	flags.BoolVar(&params.Visualise, "visualise", params.Visualise, "Write DOT code to stdout, that can then be turned into a diagram using Graphviz.")
	flags.BoolVar(&params.Cumulative, "cumulative", params.Cumulative, "Accumulate all files in a directory rather than process them independently.")
	flags.BoolVar(&params.NoFamily, "nofamily", params.NoFamily, "Don't interpret MyFamily relationships as Sybils.")
	flags.StringVar(&params.DescriptorDir, "descdir", params.DescriptorDir, "Path to directory containing router descriptors.")
	flags.StringVar(&params.ArchiveData, "data", params.ArchiveData, "File or directory to analyse.  It must contain network statuses or relay descriptors.")
	flags.StringVar(&params.InputData, "input", params.InputData, "File or directory to analyse.  It must contain network statuses or relay descriptors.")
	flags.StringVar(&params.OutputDir, "output", params.OutputDir, "Directory where analysis results are written to.")
	flags.StringVar(&params.ReferenceRelay, "referencerelay", params.ReferenceRelay, "Relay that's used as reference for nearest neighbour search.")

	err := flags.Parse(arguments)
	if err != nil {
		log.Fatal("Aborting because couldn't parse arguments: %s\n", err)
	}

	return params
}

// ParseConfig parses the configuration file ~/.sybilhunterrc.  Every line in
// the file is interpreted as command line argument.
func ParseConfig() *CmdLineParams {

	user, err := user.Current()
	if err != nil {
		log.Printf("%s.  Not reading config file.\n", err)
		return nil
	}

	file, err := os.Open(path.Join(user.HomeDir, configFile))
	if err != nil {
		log.Printf("%s.  Not reading config file.\n", err)
		return nil
	}
	defer file.Close()

	log.Println("Attempting to parse configuration file.")

	// Turn config file content into format that we can run flag.Parse() on.
	scanner := bufio.NewScanner(file)
	var arguments []string = make([]string, 0)
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Split(line, " ")
		for _, word := range words {
			arguments = append(arguments, word)
		}
	}

	log.Printf("Configuration arguments: %s\n", arguments)

	return ParseFlagSet(arguments, nil)
}

func main() {

	var threshold float64

	log.Printf("Command line arguments: %s\n", os.Args[1:])

	// Read config file first.
	params := ParseConfig()

	// Let command line arguments overwrite arguments in config file.
	params = ParseFlagSet(os.Args[1:], params)

	if params.ShowVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if params.ArchiveData == "" {
		log.Fatalln("No file or directory given.  Please use the -data switch.")
	}

	if params.Matrix {
		if threshold == 0 {
			log.Println("You might want to use -threshold to only consider similarities above or equal to the given threshold.")
		}
		params.Callbacks = append(params.Callbacks, SimilarityMatrix)
	}

	if params.Fingerprints {
		params.Callbacks = append(params.Callbacks, AnalyseFingerprints)
	}

	if params.PrintFiles {
		params.Callbacks = append(params.Callbacks, PrettyPrint)
	}

	if params.Neighbours != -1 {
		if params.Neighbours < 1 {
			log.Fatalf("Number of neighbours should be > 0, but %d given.\n", params.Neighbours)
		}
		if params.ReferenceRelay == "" {
			log.Fatalln("No reference relay given.  Please use the -referencerelay switch.")
		}
		params.Callbacks = append(params.Callbacks, FindNearestNeighbours)
	}

	if params.Churn {
		params.Callbacks = append(params.Callbacks, AnalyseChurn)
	}

	if params.Contrib {
		if params.InputData == "" {
			log.Fatalln("Need a file containing IP address blocks, one per line.  Use -input switch.")
		}
		params.Callbacks = append(params.Callbacks, BandwidthContribution)
	}

	if params.Uptime {
		if params.InputData == "" {
			log.Println("You didn't use -input to specify the file name to write to.  Using default.")
			params.InputData = "/tmp/uptime-visualisation.jpg"
		}
		params.Callbacks = append(params.Callbacks, AnalyseUptimes)
	}

	if params.BwFraction != -1 {
		if params.BwFraction < 0 || params.BwFraction > 1 {
			log.Fatalf("Bandwidth fraction must be in [0,1], but %.3f was given.\n", params.BwFraction)
		}
		params.Callbacks = append(params.Callbacks, FindFastRelays)
	}

	if len(params.Callbacks) == 0 {
		log.Fatalln("No command given.  Please use -print, -fingerprint, -matrix, -neighbours, -bwfraction, or -churn.")
	}

	if err := ParseFiles(params); err != nil {
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
		log.Printf("Processing \"%s\" cumulatively.\n", params.ArchiveData)
		filepath.Walk(params.ArchiveData, GatherObjects(&objs, nil))

		if objs == nil {
			return errors.New("Gathered object set empty.  Are we parsing the right files?")
		}

		// Send accumulated object set to all callback functions.
		for _, channel := range channels {
			channel <- objs
		}
	} else {
		log.Printf("Processing \"%s\" independently.\n", params.ArchiveData)
		filepath.Walk(params.ArchiveData, GatherObjects(nil, channels))
	}

	// Close processing channels and wait for goroutines to finish.
	for _, channel := range channels {
		close(channel)
	}
	group.Wait()

	return nil
}
