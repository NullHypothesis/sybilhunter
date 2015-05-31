// Visualises Sybil clusters.

package main

import (
	"fmt"
	"log"
	"strings"
)

// GenerateDOTGraph generates DOT graph code out of the given Sybil cluster.
// This code can then be compiled using dot(1).
func GenerateDOTGraph(cluster *SybilCluster) {

	fmt.Println("graph sybils {")
	fmt.Println("node [fillcolor=\"#dddddd\", style=\"filled,solid\"]")
	fmt.Println("edge [fontsize=8]")

	for _, pair := range cluster.SybilPairs {
		fmt.Printf("\t\"%s\\n%s\" -- \"%s\\n%s\" [label=\" %s\"];\n",
			pair.desc1.Nickname,
			pair.desc1.Fingerprint[:8],
			pair.desc2.Nickname,
			pair.desc2.Fingerprint[:8],
			strings.Replace(pair.String(), "\n", "\\l", -1))

		// Add Atlas URLs to relay nodes.
		fmt.Printf("\"%s\\n%s\" [URL=\"https://atlas.torproject.org/#details/%s\"]\n",
			pair.desc1.Nickname,
			pair.desc1.Fingerprint[:8],
			pair.desc1.Fingerprint)

		fmt.Printf("\"%s\\n%s\" [URL=\"https://atlas.torproject.org/#details/%s\"]\n",
			pair.desc2.Nickname,
			pair.desc2.Fingerprint[:8],
			pair.desc2.Fingerprint)
	}

	fmt.Println("}")

	log.Println("Compile DOT output by running: dot -o sybils.svg -Tsvg graph.dot")
}
