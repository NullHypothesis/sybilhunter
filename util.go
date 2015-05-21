// util provides a number of utility functions.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	tor "git.torproject.org/user/phw/zoossh.git"
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

// MaxUInt64 returns the larger of the two given integers.
func MaxUInt64(a, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

// MinUInt64 returns the smaller of the two given integers.
func MinUInt64(a, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// MaxUInt16 returns the larger of the two given integers.
func MaxUInt16(a, b uint16) uint16 {
	if a > b {
		return a
	} else {
		return b
	}
}

// MinUInt16 returns the smaller of the two given integers.
func MinUInt16(a, b uint16) uint16 {
	if a < b {
		return a
	} else {
		return b
	}
}

// RouterFlagsToString converts a RouterFlags struct to a constant-size string
// containing a series of bits.
func RouterFlagsToString(flags *tor.RouterFlags) string {

	// Convert a boolean value to 1 or 0.
	b2i := func(flag bool) int {
		if flag == true {
			return 1
		} else {
			return 0
		}
	}

	return fmt.Sprintf("%d%d%d%d%d%d%d%d%d%d%d%d%d",
		b2i(flags.Authority),
		b2i(flags.BadExit),
		b2i(flags.Exit),
		b2i(flags.Fast),
		b2i(flags.Guard),
		b2i(flags.HSDir),
		b2i(flags.Named),
		b2i(flags.Stable),
		b2i(flags.Running),
		b2i(flags.Unnamed),
		b2i(flags.Valid),
		b2i(flags.V2Dir),
		b2i(flags.Authority))
}
