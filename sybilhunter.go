// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
)

const (
	version    = "2015.01.a"
	timeLayout = "2006-01-02_15:04:05"
)

// Files for manual analysis are written to this directory.
var outputDir string

// isAllEmpty returns true if all given strings are empty.
func isAllEmpty(strings ...string) bool {

	for _, s := range strings {
		if s != "" {
			return false
		}
	}
	return true
}

func main() {

	var differenceThreshold int

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	archive := flag.String("archive", "", "Analyse a directory containing archived Tor network statuses.")
	similarity := flag.String("similarity", "", "Calculate pairwise similarities for all files in the given file or directory.")
	printFiles := flag.String("print", "", "Print the content of all files in the given file or directory.")
	fingerprints := flag.String("fingerprint", "", "Analyse relay fingerprints in the given file or directory.")
	flag.IntVar(&differenceThreshold, "threshold", 50, "Dump consensus when new fingerprints exceed given threshold.")
	flag.StringVar(&outputDir, "output", "", "Directory where analysis results are written to.")
	reverse := flag.Bool("reverse", false, "Parse given archive in reverse order.")
	cumulative := flag.Bool("cumulative", false, "Accumulate all files rather than process them independently.")

	flag.Parse()

	if isAllEmpty(*archive, *fingerprints, *similarity, *printFiles) && !(*showVersion) {
		log.Fatalln("No commands given.  Supported commands: -archive, -fingerprint, -similarity, -print, -version")
	}

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if *similarity != "" {
		AnalyseSimilarities(*similarity, *cumulative)
	}

	if *fingerprints != "" {
		AnalyseFingerprints(*fingerprints)
	}

	if *printFiles != "" {
		PrettyPrint(*printFiles)
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
