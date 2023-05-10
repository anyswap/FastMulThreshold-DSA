package common

import (
	"compress/gzip"
	"io"
)

func Compress(writer io.Writer, reader io.Reader) error {
	w := gzip.NewWriter(writer)
	_, err := io.Copy(w, reader)
	if err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return nil
}

func Decompress(writer io.Writer, reader io.Reader) error {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	_, err = io.Copy(writer, gzipReader)
	if err != nil {
		return err
	}
	return nil
}
