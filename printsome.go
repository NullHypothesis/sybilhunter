// Pretty-print objects identified by given fingerprints for easy grepping.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

const (
	// Length of fingerprints in characters.
	fingerprintLength = 40
)

type FingerprintSet map[tor.Fingerprint]bool

// LooksLikeFingerprint returns nil if the given blurb looks like a
// fingerprint, otherwise it returns an error.
func LooksLikeFingerprint(blurb string) error {

	if len(blurb) != fingerprintLength {
		return fmt.Errorf("\"%s\" does not look like fingerprint because it's not 40 characters in length.", blurb)
	}

	if match, _ := regexp.MatchString("^[0-9A-F]{40}$", blurb); !match {
		return fmt.Errorf("\"%s\" does not look like a fingerprint because it doesn't consist of 0-9 and A-F.", blurb)
	}

	return nil
}

// LoadFingerprints loads newline-separated fingerprints from the given file
// and returns a map with all fingerprints.
func LoadFingerprints(fileName string) FingerprintSet {

	fprset := make(FingerprintSet)

	fd, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if err := LooksLikeFingerprint(line); err != nil {
			log.Fatalf("Error while reading %s: %s", fileName, err)
		}

		fprset[tor.Fingerprint(line)] = true
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return fprset
}

// PrintSome prints all objects for which we have the fingerprint.  The output
// is meant to be human-readable and easy to analyse and grep.
func PrintSome(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	fprset := LoadFingerprints(params.InputData)
	counter := 0

	for objects := range channel {
		for object := range objects.Iterate(params.Filter) {
			switch obj := object.(type) {
			case *tor.RouterStatus:
				if _, exists := fprset[object.GetFingerprint()]; exists == true {
					counter += 1
					PrintInfo(params.DescriptorDir, obj)
				}
			case *tor.RouterDescriptor:
				if _, exists := fprset[object.GetFingerprint()]; exists == true {
					counter += 1
					fmt.Println(obj)
				}
			}
		}
	}
	log.Printf("Printed %d objects.\n", counter)
}
