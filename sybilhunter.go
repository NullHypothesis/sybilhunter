// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const (
	version = "2015.01.a"
)

func main() {

	defaultArchive := "/path/to/files/"
	var differenceThreshold int

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	archive := flag.String("archive", defaultArchive, "Analyse a directory containing archives Tor data formats.")
	flag.IntVar(&differenceThreshold, "threshold", 50, "Dump consensus when new fingerprints exceed given threshold.")
	reverse := flag.Bool("reverse", false, "Parse given archive in reverse order.")

	flag.Parse()

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if *archive != defaultArchive {

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
