//  Copyright (c) 2022 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"go.fd.io/govpp"
	"go.fd.io/govpp/binapigen"
	"go.fd.io/govpp/binapigen/vppapi"
)

const (
	generateLogFname = "generate.log"
)

func GenerateAll(gen *binapigen.Generator) []*binapigen.GenFile {
	genOpts := gen.GetOpts()

	logrus.Infof("[WRAPPERGEN] GenerateAll (opts: %+v)", genOpts)

	outputDir := filepath.Join(genOpts.OutputDir, "..")

	if vppDir := os.Getenv("VPP_DIR"); vppDir != "" {
		createGenerateLog(vppDir, filepath.Join(outputDir, generateLogFname))
	}

	return nil
}

func createGenerateLog(apiDir string, fname string) {
	vppSrcDir, err := findGitRepoRootDir(apiDir)
	if err != nil {
		return
	}

	vppVersion, err := vppapi.GetVPPVersionRepo(vppSrcDir)
	if err != nil {
		logrus.Fatalf("Unable to get vpp version : %s", err)
	}

	cmd := exec.Command("bash", "-c", "git log --oneline -1 $(git log origin/master..HEAD --oneline | tail -1 | awk '{print $1}')")
	cmd.Dir = vppSrcDir
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		logrus.Fatalf("Unable to get vpp base commit : %s", out)
	}
	lastCommit := strings.TrimSpace(string(out))

	cmd = exec.Command("git", "log", "origin/master..HEAD", "--pretty=%s")
	cmd.Dir = vppSrcDir
	cmd.Stderr = os.Stderr
	out, err = cmd.Output()
	if err != nil {
		logrus.Fatalf("Unable to get vpp own branch commits : %s", out)
	}
	ownCommits := strings.TrimSpace(string(out))

	value := fmt.Sprintf("VPP Version                 : %s\n", vppVersion)
	value += fmt.Sprintf("Binapi-generator version    : %s\n", govpp.Version())
	value += fmt.Sprintf("VPP Base commit             : %s\n", lastCommit)
	value += "------------------ Cherry picked commits --------------------\n"
	value += fmt.Sprintf("%s\n", ownCommits)
	value += "-------------------------------------------------------------\n"

	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		logrus.Fatalf("Unable to open file %s %s", fname, err)
	}
	n, err := f.Write([]byte(value))
	if err != nil || n < len(value) {
		logrus.Fatalf("Unable to write to file %s %s", fname, err)
	}
	err = f.Close()
	if err != nil {
		logrus.Fatalf("Unable to close file %s %s", fname, err)
	}
}

func findGitRepoRootDir(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git command failed: %v\noutput: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
