package main

import (
	"os"
	"path/filepath"
)

func openManifest(dir string) (*os.File, error) {
	return os.Open(filepath.Join(dir, "manifest.jsonl"))
}
