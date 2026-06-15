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

package types

import (
	"fmt"
)

type SessionRedirect struct {
	FiveTuple
	TableIndex  uint32
	IsPunt      bool
	OpaqueIndex uint32
}

func (sr *SessionRedirect) String() string {
	return fmt.Sprintf("[tbl:%d %s]", sr.TableIndex, sr.FiveTuple.String())
}

func (sr *SessionRedirect) VppString() string {
	match, err := sr.GetMatch()
	if err != nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%x", match)
}
