package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestPrintFiles(t *testing.T) {
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" && path != "main_test.go" {
			fmt.Printf("--- FILE: %s ---\n", path)
			content, _ := ioutil.ReadFile(path)
			fmt.Println(string(content))
		}
		return nil
	})
	t.Fail()
}
