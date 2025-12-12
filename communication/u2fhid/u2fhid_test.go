// SPDX-License-Identifier: Apache-2.0

package u2fhid

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// testRW mocks io.ReadWriteCloser with variable write chunk handling
type testRW struct {
	writeBuffer    bytes.Buffer
	writeChunkSize int // max bytes to write per call
}

func (t *testRW) Write(p []byte) (n int, err error) {
	if t.writeChunkSize == 0 || t.writeChunkSize > len(p) {
		t.writeBuffer.Write(p)
		return len(p), nil
	}

	written := t.writeChunkSize
	t.writeBuffer.Write(p[:written])
	return written, nil
}

func (t *testRW) Read(p []byte) (n int, err error) { return 0, nil }
func (t *testRW) Close() error                     { return nil }

func generateExpectedFrame(cmd byte, message string) []byte {
	buf := new(bytes.Buffer)

	// Handle empty message case
	if len(message) == 0 {
		return buf.Bytes()
	}

	// Init packet
	binary.Write(buf, binary.BigEndian, cid)
	buf.WriteByte(cmd)
	binary.Write(buf, binary.BigEndian, uint16(len(message)))

	// Split the message into init part and remaining
	remaining := message
	initData := remaining[:min(len(remaining), 57)]
	remaining = remaining[len(initData):]
	buf.WriteString(initData)
	if len(initData) < 57 {
		buf.Write(bytes.Repeat([]byte{0xee}, 57-len(initData)))
	}

	// Continue with remaining data for continuation frames
	for seq := 0; len(remaining) > 0; seq++ {
		cont := new(bytes.Buffer)
		binary.Write(cont, binary.BigEndian, cid)
		cont.WriteByte(uint8(seq))

		contData := remaining[:min(len(remaining), 59)]
		cont.WriteString(contData)
		remaining = remaining[len(contData):]
		if cont.Len() < 64 {
			cont.Write(bytes.Repeat([]byte{0xee}, 64-cont.Len()))
		}
		buf.Write(cont.Bytes())
	}

	return buf.Bytes()
}

func TestSendFrame(t *testing.T) {
	const testCMD = 0xab

	tests := []struct {
		name           string
		input          string
		chunkSize      int
		expectedFrames string
	}{
		{
			name:           "empty message",
			input:          "",
			chunkSize:      64,
			expectedFrames: "",
		},
		{
			name:           "small message (exact init frame)",
			input:          strings.Repeat("a", 57),
			chunkSize:      64,
			expectedFrames: strings.Repeat("a", 57),
		},
		{
			name:           "message requiring one continuation frame",
			input:          strings.Repeat("b", 58),
			chunkSize:      32,
			expectedFrames: strings.Repeat("b", 58),
		},
		{
			name:           "multi-frame message with uneven writes",
			input:          strings.Repeat("c", 500),
			chunkSize:      7,
			expectedFrames: strings.Repeat("c", 500),
		},
		{
			name:           "boundary case with minimal writes",
			input:          strings.Repeat("d", 64*3),
			chunkSize:      1,
			expectedFrames: strings.Repeat("d", 64*3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &testRW{writeChunkSize: tt.chunkSize}
			comm := NewCommunication(rw, testCMD)

			err := comm.SendFrame(tt.input)
			if err != nil {
				t.Fatalf("SendFrame failed: %v", err)
			}

			expected := generateExpectedFrame(testCMD, tt.input)
			actualCount := rw.writeBuffer.Len() / 64 * 64
			actual := rw.writeBuffer.Bytes()[:actualCount]

			if !bytes.Equal(expected, actual) {
				t.Errorf("Frame mismatch\nExpected:\n% x\n\nGot:\n% x", expected, actual)
			}

			// Verify all padding bytes
			totalFrames := len(expected) / 64
			for frameNum := range totalFrames {
				frameStart := frameNum * 64
				frameEnd := (frameNum + 1) * 64
				frame := expected[frameStart:frameEnd]

				// Check CID in every frame
				if binary.BigEndian.Uint32(frame[0:4]) != cid {
					t.Error("Invalid CID in frame")
				}

				if frameNum == 0 {
					// Init frame checks
					if frame[4] != testCMD {
						t.Error("Invalid command byte in init frame")
					}

					dataLength := binary.BigEndian.Uint16(frame[5:7])
					if dataLength != uint16(len(tt.input)) {
						t.Error("Invalid data length in init frame")
					}
				} else if frame[4] != byte(frameNum-1) {
					// Continuation frame checks
					t.Error("Invalid sequence number in continuation frame")
				}

				// Verify padding bytes (last byte of filled data to end)
				dataEnd := len(tt.input) - (57 + (frameNum-1)*59)
				if frameNum > 0 && dataEnd < 0 {
					dataEnd = 0
				}
				paddingStart := 7 + dataEnd
				if frameNum == 0 {
					paddingStart = 7 + min(len(tt.input), 57)
				}

				if paddingStart < 64 {
					paddingBytes := frame[paddingStart:]
					for _, b := range paddingBytes {
						if b != 0xee {
							t.Errorf("Invalid padding byte: %02x", b)
						}
					}
				}
			}
		})
	}
}
