package main

import (
	"fmt"
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

	return func(fileName string) error {

		currCons, err = tor.ParseConsensusFile(fileName)
		if err != nil {
			return err
		}

		// Determine and print the amount of previously unknown relay
		// fingerprints.
		if allCons.Length() != 0 {
			fmt.Printf("%s, ", filepath.Base(fileName))

			unobserved := currCons.Subtract(allCons)
			fmt.Printf("%d\n", unobserved.Length())
		}

		// Only keep track of fingerprints and discard the router statuses
		// because we don't need them.
		for fingerprint, _ := range currCons.RouterStatuses {
			allCons.Set(fingerprint, nil)
		}

		return nil
	}
}
