// Copyright (C) 2022 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCleanupCoreFiles creates 4 files names file1..file3
// it then calls CleanupCoreFiles() with maxCoreFiles=2 (default)
// we assert that only file2 & file3 remain
// then call CleanupCoreFiles() with maxCoreFiles=0
// and assert no file remain
func TestCleanupCoreFiles(t *testing.T) {
	err := CleanupCoreFiles("")
	if err != nil {
		t.Errorf("Error calling CleanupCoreFiles(\"\") %s", err)
	}

	dir, err := os.MkdirTemp("", "TestCleanupCoreFiles")
	if err != nil {
		t.Errorf("Error MkdirTemp %s", err)
	}
	for i := 0; i < 4; i++ {
		err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file%d", i)), []byte("data"), 0666)
		if err != nil {
			t.Errorf("Error WriteFile %d %s", 1, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"))
	if err != nil {
		t.Errorf("Error calling CleanupCoreFiles %s", err)
	}
	for i := 0; i < 2; i++ {
		_, err = os.Stat(filepath.Join(dir, fmt.Sprintf("file%d", i)))
		if !os.IsNotExist(err) {
			t.Errorf("file%d err is not ErrNotExist %s", i, err)
		}
	}
	for i := 2; i < 4; i++ {
		_, err = os.Stat(filepath.Join(dir, fmt.Sprintf("file%d", i)))
		if err != nil {
			t.Errorf("file%d stat errored %s", i, err)
		}
	}

	maxCoreFiles = 0
	err = CleanupCoreFiles(filepath.Join(dir, "vppcore.%e.%p"))
	if err != nil {
		t.Errorf("Error calling CleanupCoreFiles() max=0 %s", err)
	}

	err = os.Remove(dir)
	if err != nil {
		t.Errorf("Error calling os.Remove %s", err)
	}
}
