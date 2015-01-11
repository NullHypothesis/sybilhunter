// sybilhunter hunts for sybils in the Tor anonymity network.
package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"

	tor "git.torproject.org/user/phw/zoossh.git"
)

const (
	version = "2015.01.a"
)

// countNewFingerprints determines the amount of new fingerprints between two
// subsequent consensus documents.  It does so by finding fingerprints which
// are part of set2 but not set1.
func countNewFingerprints(set1 map[string]*tor.RouterStatus, set2 map[string]*tor.RouterStatus) uint {

	newFingerprints := uint(0)

	for fingerprint, _ := range set2 {
		_, exists := set1[fingerprint]
		if !exists {
			newFingerprints += 1
		}
	}

	return newFingerprints
}

// walker walks through the provided path and attempts to parse all
// consensus documents found within.  After parsing, it determines the amount
// of new relay fingerprints in between two subsequent consensus documents.
func walker() func(path string, info os.FileInfo, err error) error {

	var prevCons = make(map[string]*tor.RouterStatus)
	var currCons = make(map[string]*tor.RouterStatus)

	return func(path string, info os.FileInfo, err error) error {

		if !info.IsDir() {
			currCons, err = tor.ParseConsensusFile(path)
			if err != nil {
				return err
			}

			if len(prevCons) != 0 {
				fmt.Printf("%s has %d new relay fingerprints.\n",
					path, countNewFingerprints(prevCons, currCons))
			}

			for key, val := range currCons {
				prevCons[key] = val
			}
		}

		return nil
	}
}

func main() {

	defaultArchive := "/path/to/files/"

	// Handle command line arguments.
	showVersion := flag.Bool("version", false, "Show version number and exit.")
	archive := flag.String("archive", defaultArchive,
		"Analyse a directory containing archives Tor data formats.")

	flag.Parse()

	if *showVersion {
		_, execName := path.Split(os.Args[0])
		fmt.Printf("%s v%s\n", execName, version)
		os.Exit(0)
	}

	if *archive != defaultArchive {
		filepath.Walk(*archive, walker())
	}
}
