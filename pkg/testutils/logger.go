// Copyright (C) 2025 Cisco Systems Inc.
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

package testutils

import (
	. "github.com/onsi/ginkgo/v2"
)

// LogSection logs a section header.
func LogSection(title string) {
	GinkgoWriter.Printf("\n=== %s ===\n", title)
}

// LogStep logs a test step with arrow prefix.
func LogStep(format string, args ...interface{}) {
	GinkgoWriter.Printf("  → "+format+"\n", args...)
}

// LogSuccess logs a success message with checkmark prefix.
func LogSuccess(format string, args ...interface{}) {
	GinkgoWriter.Printf("  ✓ "+format+"\n", args...)
}

// LogInfo logs an info message.
func LogInfo(format string, args ...interface{}) {
	GinkgoWriter.Printf("  "+format+"\n", args...)
}
