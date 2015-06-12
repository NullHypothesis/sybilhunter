// Pretty-print objects for easy grepping.

package main

import (
	"fmt"
	"log"
	"sync"

	tor "git.torproject.org/user/phw/zoossh.git"
)

// PrettyPrint prints all objects within the object sets received over the
// given channel.  The output is meant to be human-readable and easy to analyse
// and grep.
func PrettyPrint(channel chan tor.ObjectSet, params *CmdLineParams, group *sync.WaitGroup) {

	defer group.Done()

	counter := 0
	for objects := range channel {
		for object := range objects.Iterate() {
			fmt.Println(object)
			counter += 1
		}
	}
	log.Printf("Printed %d objects.\n", counter)
}
