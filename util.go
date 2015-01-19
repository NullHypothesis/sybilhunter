// util provides a number of utility functions.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"
)

// getOutputDir returns the directory to which files can be written to.  If it
// is not set by the user, we randomly generate a new one in /tmp/.
func getOutputDir() (string, error) {

	var err error

	// The user did not point us to a directory, so we have to create a new
	// one.
	if outputDir == "" {
		fileName := fmt.Sprintf("sybilhunter_%s_", time.Now().Format(timeLayout))
		outputDir, err = ioutil.TempDir("/tmp/", fileName)
		if err != nil {
			return "", err
		}

		log.Printf("Created output directory \"%s\".\n", outputDir)
	}

	return outputDir, nil
}

// writeStringToFile writes the given string blurb to a randomly generated file
// with the given string prefix.  The file is placed in the output directory
// which can bet set by the user.
func writeStringToFile(fileName string, content string) error {

	directory, err := getOutputDir()
	if err != nil {
		return err
	}

	fd, err := ioutil.TempFile(directory, fmt.Sprintf("%s_", fileName))
	if err != nil {
		return err
	}

	fmt.Fprint(fd, content)
	log.Printf("Wrote %d-byte string to \"%s\".\n", len(content), fd.Name())

	return nil
}
