// SPDX-License-Identifier: Apache-2.0

// Package usart implements a framing protocol for messages sent over UART.
package usart

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
)

const version byte = 0x01
const endpointError = 0xff

// ErrEndpointUnavailable is returned if the device returns an endpoint error, which means we are
// talking to the wrong endpoint (firmware vs. bootloader).
var ErrEndpointUnavailable = errors.New("endpoint not available")

func newBuffer() *bytes.Buffer {
	// This needs to be allocated exactly like this (not with nil or new(bytes.Buffer) etc), so that
	// the memory address of the actual bytes does not change.
	// See https://github.com/golang/go/issues/14210#issuecomment-370468469
	return bytes.NewBuffer([]byte{})
}

// Communication implements a framing protocol for messages sent over UART.
type Communication struct {
	device io.ReadWriteCloser
	mutex  sync.Mutex
	cmd    byte
}

// NewCommunication creates a new Communication.
// cmd is the U2F CMD byte which is sent and which is expected in responses.
func NewCommunication(
	device io.ReadWriteCloser,
	cmd byte,
) *Communication {
	return &Communication{
		device: device,
		mutex:  sync.Mutex{},
		cmd:    cmd,
	}
}

// SendFrame sends one message enclosed in a usart frame.
func (communication *Communication) SendFrame(msg []byte) error {
	communication.mutex.Lock()
	defer communication.mutex.Unlock()
	return communication.sendFrame(msg)
}

func computeChecksum(data []byte) []byte {
	var result uint32
	for i := 0; i < len(data); i += 2 {
		b1 := data[i]
		b2 := byte(0x00)
		if i < len(data)-1 {
			b2 = data[i+1]
		}
		result += uint32(binary.LittleEndian.Uint16([]byte{b1, b2}))
		if result > 0xFFFF {
			result -= 0xFFFF
		}
	}
	resultBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(resultBytes, uint16(result))
	return resultBytes
}

func encodeUsartFrame(msg []byte) []byte {
	buf := newBuffer()
	buf.WriteByte(0x7e)
	msg = bytes.ReplaceAll(msg, []byte{0x7d}, []byte{0x7d, 0x7d ^ 0x20})
	msg = bytes.ReplaceAll(msg, []byte{0x7e}, []byte{0x7d, 0x7e ^ 0x20})
	buf.Write(msg)
	buf.WriteByte(0x7e)
	return buf.Bytes()
}

func (communication *Communication) sendFrame(msg []byte) error {
	buf := newBuffer()
	buf.WriteByte(version)
	buf.WriteByte(communication.cmd)
	buf.Write(msg)
	checksum := computeChecksum(buf.Bytes())
	buf.Write(checksum)
	if buf.Len() > 5000 {
		return errp.Newf("data size over 5000 bytes")
	}
	_, err := communication.device.Write(encodeUsartFrame(buf.Bytes()))
	return errp.WithMessage(errp.WithStack(err), "failed to send message")
}

// ReadFrame reads a message encoded in a usart frame.
func (communication *Communication) ReadFrame() ([]byte, error) {
	communication.mutex.Lock()
	defer communication.mutex.Unlock()
	return communication.readFrame()
}

func decodeUsartFrame(reader io.Reader) ([]byte, error) {
	// TODO: think about buffering
	read := make([]byte, 1)
	foundBeginning := false
	escaped := false
	buf := newBuffer()
	for {
		readLen, err := reader.Read(read)
		if err != nil {
			return nil, errp.WithStack(err)
		}
		if readLen != 1 {
			return nil, errp.New("expected to be able to read")
		}
		readByte := read[0]

		// Skip until 0x7e
		if !foundBeginning {
			if readByte == 0x7e {
				foundBeginning = true
			}
			continue
		}

		if readByte == 0x7d {
			escaped = true
			continue
		}
		if readByte == 0x7e {
			break
		}
		if escaped {
			readByte ^= 0x20
			escaped = false
		}
		buf.WriteByte(readByte)
	}
	return buf.Bytes(), nil
}

func (communication *Communication) readFrame() ([]byte, error) {
	data, err := decodeUsartFrame(communication.device)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, errp.New("expected at least 4 bytes (version 1, cmd 1, checksum 2)")
	}
	replyVersion, cmd := data[0], data[1]
	if replyVersion != version {
		return nil, errp.Newf("unexpected version %v, expected %v", replyVersion, version)
	}
	data, expectedChecksum := data[:len(data)-2], data[len(data)-2:]
	checksum := computeChecksum(data)
	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, errp.Newf("checksum mismatch, expected: %v, got: %v", expectedChecksum, checksum)
	}
	if cmd == endpointError {
		return nil, ErrEndpointUnavailable
	}
	if cmd != communication.cmd {
		return nil, errp.Newf("unexpected cmd %v, expected %v", cmd, communication.cmd)
	}
	return data[2:], nil
}

// Close closes the underlying device.
func (communication *Communication) Close() {
	if err := communication.device.Close(); err != nil {
		panic(err)
	}
}

// Query sends a request and waits for the response. Blocking.
func (communication *Communication) Query(request []byte) ([]byte, error) {
	communication.mutex.Lock()
	defer communication.mutex.Unlock()
	if err := communication.sendFrame(request); err != nil {
		return nil, err
	}
	return communication.readFrame()
}
