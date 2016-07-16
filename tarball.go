package main

import (
	"archive/tar"
	"io"
	"os"
	"os/exec"
)

// Decompress the given io.Reader and return a new io.ReadCloser containing the
// decompressed output.
//
// This function requires the xz command to be installed.
func xzReader(r io.Reader) (io.ReadCloser, error) {

	cmd := exec.Command("xz", "--decompress", "--stdout")
	cmd.Stdin = r

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	return stdout, nil
}

// Open an xz-compressed tar file.
//
// Returns the underlying tar.xz file descriptor (so you can close it), as well
// as a *tar.Reader over the decompressed file contents.
func openTarXZFile(fileName string) (*os.File, *tar.Reader, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, nil, err
	}

	xzr, err := xzReader(fd)
	if err != nil {
		fd.Close()
		return nil, nil, err
	}

	return fd, tar.NewReader(xzr), nil
}
