// archives analyses consensuses as archived by CollecTor.
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// collectFiles returns a closure of type WalkFunc which is used to collect all
// file names in a given directory.
func collectFiles(fileNames *[]string) func(path string, info os.FileInfo, err error) error {

	return func(path string, info os.FileInfo, err error) error {

		if !info.IsDir() {
			*fileNames = append(*fileNames, path)
		}

		return nil
	}
}

// logConsensus writes the given consensus to a file which is put in the output
// directory.
func logConsensus(fileName string, consensus *tor.Consensus) {

	// Convert the given (partial) consensus to a string blurb.
	var buffer bytes.Buffer
	for _, getStatus := range consensus.RouterStatuses {
		buffer.WriteString(fmt.Sprint(getStatus()))
	}

	err := writeStringToFile(filepath.Base(fileName), buffer.String())
	if err != nil {
		log.Panicln(err)
	}
}

// getArchiveParser returns a closure which takes a file name of a network
// consensus, parses it, and determines the amount of previously unobserved
// relay fingerprints in it compared to all previously observed file names.
// Depending on if the file names are sorted in lexical or reverse lexical
// order, this tells us how many relays join or leave the network,
// respectively.
func getArchiveParser(threshold int) func(fileName string) error {

	var allCons = tor.NewConsensus()
	var currCons = tor.NewConsensus()
	var err error

	directory, err := getOutputDir()
	if err != nil {
		log.Panicln(err)
	}

	fd, err := ioutil.TempFile(directory, fmt.Sprintf("analysis_results_"))
	log.Printf("Writing analysis results to \"%s\".\n", fd.Name())
	if err != nil {
		log.Panicln(err)
	}

	return func(fileName string) error {

		currCons, err = tor.LazilyParseConsensusFile(fileName)
		if err != nil {
			return err
		}

		// Determine and print the amount of previously unknown relay
		// fingerprints.
		if allCons.Length() != 0 {
			fmt.Fprintf(fd, "%s, ", filepath.Base(fileName))

			unobserved := currCons.Subtract(allCons)
			fmt.Fprintf(fd, "%d\n", unobserved.Length())

			// Dump previously unobserved statuses to file for manual analysis.
			if unobserved.Length() > threshold {
				log.Printf("Observed change in \"%s\" exceeds threshold by %d.\n",
					filepath.Base(fileName), unobserved.Length()-threshold)
				logConsensus(filepath.Base(fileName), unobserved)
			}
		}

		// Only keep track of fingerprints and discard the router statuses
		// because we don't need them.
		for fingerprint, _ := range currCons.RouterStatuses {
			allCons.Set(fingerprint, nil)
		}

		return nil
	}
}
