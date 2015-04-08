// Print the content of files for easy grepping.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// printFiles prints the content of all supported files found in the provided
// directory or file.
func printFiles(path string, info os.FileInfo, err error) error {

	if _, err = os.Stat(path); err != nil {
		log.Printf("File \"%s\" does not exist.\n", path)
		return nil
	}

	if info.IsDir() {
		return nil
	}

	log.Printf("Parsing file \"%s\".\n", path)
	objects, err := tor.ParseUnknownFile(path)
	if err != nil {
		log.Printf("%s", err)
		// Return nil because we don't want to abort walking after this error.
		return nil
	}

	counter := 0
	for obj := range objects.Iterate() {
		fmt.Println(obj)
		counter += 1
	}
	log.Printf("Printed %d objects.\n", counter)

	return nil
}

// PrettyPrint calls printFiles for all files in the provided file or
// directory.
func PrettyPrint(path string) {

	filepath.Walk(path, printFiles)
}
