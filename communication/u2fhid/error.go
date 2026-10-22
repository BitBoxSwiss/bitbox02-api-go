// Copyright 2018-2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package u2fhid

import "fmt"

const (
	errCodeChannelBusy = byte(0x06)

	// errCodeChannelNone         = byte(0x00)
	// errCodeChannelInvalidCmd   = byte(0x01)
	// errCodeChannelInvalidPar   = byte(0x02)
	// errCodeChannelInvalidLen   = byte(0x03)
	// errCodeChannelInvalidSeq   = byte(0x04)
	// errCodeChannelMsgTimeout   = byte(0x05)
	// errCodechannellockRequired = byte(0x0A)
	// errCodechannelInvalidCid   = byte(0x0B)
	// errCodechannelOther        = byte(0x7F)
)

// FrameError is returned when the frame which is read indicates an error.
// The value within is the error code.
type FrameError byte

// Error implements error.
func (e FrameError) Error() string {
	return fmt.Sprintf("frame error: %d", e)
}

// IsErrBusy returns true if the error code indicates a busy channel.
func (e FrameError) IsErrBusy() bool {
	return byte(e) == errCodeChannelBusy
}
