// SPDX-License-Identifier: Apache-2.0

package u2fhid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type packetDevice struct {
	packets [][]byte
}

func (device *packetDevice) Read(dst []byte) (int, error) {
	if len(device.packets) == 0 {
		return 0, io.EOF
	}
	packet := device.packets[0]
	if len(packet) > len(dst) {
		return 0, io.ErrShortBuffer
	}
	device.packets = device.packets[1:]
	return copy(dst, packet), nil
}

func (device *packetDevice) Write(src []byte) (int, error) { return len(src), nil }
func (device *packetDevice) Close() error                  { return nil }

// responsePackets encodes a complete payload into separately delivered HID packets.
// Padding belongs to the packet, not to the declared message payload.
func responsePackets(cmd byte, payload []byte, initialSize, continuationSize int, padded bool) [][]byte {
	initialSize = min(initialSize, len(payload))
	initial := make([]byte, 7+initialSize)
	binary.BigEndian.PutUint32(initial, cid)
	initial[4] = cmd
	binary.BigEndian.PutUint16(initial[5:], uint16(len(payload)))
	copy(initial[7:], payload[:initialSize])
	packets := [][]byte{initial}
	remaining := payload[initialSize:]
	for sequence := byte(0); len(remaining) > 0; sequence++ {
		size := min(continuationSize, len(remaining))
		packet := make([]byte, 5+size)
		binary.BigEndian.PutUint32(packet, cid)
		packet[4] = sequence
		copy(packet[5:], remaining[:size])
		packets = append(packets, packet)
		remaining = remaining[size:]
	}
	if padded {
		last := len(packets) - 1
		packets[last] = append(packets[last], bytes.Repeat([]byte{0xee}, readReportSize-len(packets[last]))...)
	}
	return packets
}

func TestReadFramePayload(t *testing.T) {
	const command = 0xc1
	for _, test := range []struct {
		name             string
		length           int
		initialSize      int
		continuationSize int
		padded           bool
	}{
		{name: "empty", initialSize: 57, continuationSize: 59},
		{name: "short single packet", length: 9, initialSize: 57, continuationSize: 59},
		{name: "padded single packet", length: 9, initialSize: 57, continuationSize: 59, padded: true},
		{name: "full initial packet", length: 57, initialSize: 57, continuationSize: 59},
		{name: "full packets", length: 211, initialSize: 57, continuationSize: 59, padded: true},
		{name: "short initial packet", length: 91, initialSize: 11, continuationSize: 59},
		{name: "header-only initial packet", length: 131, initialSize: 0, continuationSize: 59},
		{name: "short continuation packets", length: 149, initialSize: 13, continuationSize: 23},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, test.length)
			for i := range payload {
				payload[i] = byte(i + 1)
			}
			device := &packetDevice{
				packets: responsePackets(command, payload, test.initialSize, test.continuationSize, test.padded),
			}
			got, err := NewCommunication(device, command).ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %x, want %x", got, payload)
			}
			if len(device.packets) != 0 {
				t.Fatalf("left %d response packets unread", len(device.packets))
			}
		})
	}
}

func TestReadFrameIncomplete(t *testing.T) {
	const command = 0xc1
	payload := bytes.Repeat([]byte{0x42}, 91)
	packets := responsePackets(command, payload, 11, 59, false)
	for _, test := range []struct {
		name    string
		packets [][]byte
		wantErr error
		message string
	}{
		{name: "no initial packet", wantErr: io.EOF},
		{name: "short initial header", packets: [][]byte{packets[0][:6]}, message: "expected minimum read length of 7"},
		{name: "missing continuation", packets: packets[:1], wantErr: io.EOF},
		{name: "missing final continuation", packets: packets[:len(packets)-1], wantErr: io.EOF},
		{name: "short continuation header", packets: [][]byte{packets[0], packets[1][:4]}, message: "expected minimum read length of 5"},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := &packetDevice{packets: test.packets}
			got, err := NewCommunication(device, command).ReadFrame()
			if err == nil {
				t.Fatalf("expected an error, got payload %x", got)
			}
			if got != nil {
				t.Fatalf("returned partial payload %x with error %v", got, err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("got error %v, want %v", err, test.wantErr)
			}
			if test.message != "" && err.Error() != test.message {
				t.Fatalf("got error %q, want %q", err, test.message)
			}
		})
	}
}
