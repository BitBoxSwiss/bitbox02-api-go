// SPDX-License-Identifier: Apache-2.0

// Package bootloader contains the API to the physical device.
package bootloader

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
)

const (
	chunkSize       = 8 * 512
	maxFirmwareSize = 884736
	// max number of chunks that can be written when flashing the firmware.
	firmwareChunks = maxFirmwareSize / chunkSize

	numRootKeys    = 3
	numSigningKeys = 3

	magicLen              = 4
	versionLen            = 4
	signingPubkeysDataLen = versionLen + numSigningKeys*64 + numRootKeys*64
	firmwareDataLen       = versionLen + numSigningKeys*64
	sigDataLen            = signingPubkeysDataLen + firmwareDataLen
)

var sigDataMagic = map[common.Product]uint32{
	common.ProductBitBox02Multi:       0x653f362b,
	common.ProductBitBox02BTCOnly:     0x11233B0B,
	common.ProductBitBox02PlusMulti:   0x5b648ceb,
	common.ProductBitBox02PlusBTCOnly: 0x48714774,
}

// Communication contains functions needed to communicate with the device.
type Communication interface {
	SendFrame(string) error
	Query([]byte) ([]byte, error)
	Close()
}

// Status has all the info to handle the bootloader mode.
type Status struct {
	Upgrading         bool    `json:"upgrading"`
	Progress          float64 `json:"progress"`
	UpgradeSuccessful bool    `json:"upgradeSuccessful"`
	ErrMsg            string  `json:"errMsg"`
}

func toByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// Device provides the API to communicate with the BitBox02 bootloader.
type Device struct {
	communication   Communication
	version         *semver.SemVer
	product         common.Product
	development     bool
	status          *Status
	onStatusChanged func(*Status)
}

// NewDevice creates a new instance of Device.
func NewDevice(
	version *semver.SemVer,
	product common.Product,
	communication Communication,
	onStatusChanged func(*Status),
	options ...DeviceOption,
) *Device {
	device := &Device{
		communication:   communication,
		version:         version,
		product:         product,
		status:          &Status{},
		onStatusChanged: onStatusChanged,
	}
	for _, option := range options {
		option(device)
	}
	return device
}

// DeviceOption configures a bootloader device.
type DeviceOption func(*Device)

// WithDevelopment records whether this is a development bootloader.
func WithDevelopment(development bool) DeviceOption {
	return func(device *Device) { device.development = development }
}

// IsDevelopment reports whether this is a development bootloader.
func (device *Device) IsDevelopment() bool {
	return device.development
}

// Product returns the bootloader product.
func (device *Device) Product() common.Product {
	return device.product
}

// Close closes the communication.
func (device *Device) Close() {
	device.communication.Close()
}

// Status returns the progress of a firmware upgrade.
func (device *Device) Status() *Status {
	return device.status
}

func (device *Device) query(cmd rune, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteRune(cmd)
	buf.Write(data)
	reply, err := device.communication.Query(buf.Bytes())
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, errp.Newf("Unexpected reply: %v", reply)
	}
	if reply[0] != byte(cmd) || len(reply) < 2 || reply[1] != 0 {
		return nil, errp.Newf("Unexpected reply: %v", reply)
	}
	return reply[2:], nil
}

// VersionInfo contains the installed firmware, signing key and stage0 versions.
type VersionInfo struct {
	FirmwareVersion       uint32
	SigningPubkeysVersion uint32
	// Stage0Version is nil when the bootloader does not report a known stage0 version.
	Stage0Version *uint16
}

// Versions queries version information, including stage0 starting with bootloader v1.2.4.
func (device *Device) Versions() (*VersionInfo, error) {
	response, err := device.query('v', nil)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(response)
	info := &VersionInfo{}
	if err := binary.Read(reader, binary.LittleEndian, &info.FirmwareVersion); err != nil {
		return nil, errp.WithMessage(err, "invalid firmware version")
	}
	if err := binary.Read(reader, binary.LittleEndian, &info.SigningPubkeysVersion); err != nil {
		return nil, errp.WithMessage(err, "invalid signing pubkeys version")
	}
	if reader.Len() > 0 {
		var stage0Version uint16
		if err := binary.Read(reader, binary.LittleEndian, &stage0Version); err != nil {
			return nil, errp.WithMessage(err, "invalid stage0 version")
		}
		if stage0Version != 0 {
			info.Stage0Version = &stage0Version
		}
	}
	return info, nil
}

// GetHashes queries the device for the firmware and signing keydata hashes.
// If the display flags are true, the hashes are also shown on the device screen.
func (device *Device) GetHashes(displayFirmwareHash, displaySigningKeydataHash bool) (
	[]byte, []byte, error) {
	response, err := device.query('h',
		[]byte{toByte(displayFirmwareHash), toByte(displaySigningKeydataHash)})
	if err != nil {
		return nil, nil, err
	}
	if len(response) != 64 {
		return nil, nil, errp.New("unexpected response")
	}
	firmwareHash := response[:32]
	signingKeyDatahash := response[32:64]
	return firmwareHash, signingKeyDatahash, nil
}

// ShowFirmwareHashEnabled returns whether the bootloader will automatically show the firmware
// hash on boot.
func (device *Device) ShowFirmwareHashEnabled() (bool, error) {
	response, err := device.query('H', []byte{0xFF})
	if err != nil {
		return false, err
	}
	return response[0] == 1, nil
}

// SetShowFirmwareHashEnabled returns whether the bootloader will automatically show the firmware
// hash on boot.
func (device *Device) SetShowFirmwareHashEnabled(enabled bool) error {
	_, err := device.query('H', []byte{toByte(enabled)})
	return err
}

// Reboot reboots the device.
func (device *Device) Reboot() error {
	return device.communication.SendFrame("r")
}

// ScreenRotate rotates the device screen.
func (device *Device) ScreenRotate() error {
	_, err := device.query('f', nil)
	return err
}

// SecureChipModel enumerates the secure chip models in use.
type SecureChipModel string

const (
	// SecureChipModelATECC refers to the ATECC chips (e.g. ATECC608A, ATECC608B).
	SecureChipModelATECC SecureChipModel = "ATECC"
	// SecureChipModelOptiga refers to the Optiga chip (e.g. Optiga Trust M V3).
	SecureChipModelOptiga SecureChipModel = "Optiga"
)

// Hardware contains hardware info, returned by `Hardware()`.
type Hardware struct {
	// SecureChipModel contains which securechip model is on the device.
	SecureChipModel SecureChipModel
}

// Hardware returns hardware info.
func (device *Device) Hardware() (*Hardware, error) {
	// OP_HARDWARE was introduced in v1.1.0.
	if !device.version.AtLeast(semver.NewSemVer(1, 1, 0)) {
		return &Hardware{
			SecureChipModel: SecureChipModelATECC,
		}, nil
	}
	response, err := device.query('W', nil)
	if err != nil {
		return nil, err
	}
	if len(response) < 1 {
		return nil, errp.New("unexpected response")
	}

	var securechipModel SecureChipModel
	switch response[0] {
	case 0x00:
		securechipModel = SecureChipModelATECC
	case 0x01:
		securechipModel = SecureChipModelOptiga
	default:
		return nil, errp.Newf("Unrecognized securechip model: %d", response[0])
	}
	return &Hardware{
		SecureChipModel: securechipModel,
	}, nil
}

func (device *Device) erase(firmwareNumChunks uint8) error {
	_, err := device.query('e', []byte{firmwareNumChunks})
	return err
}

func (device *Device) writeChunk(chunkNum uint8, chunk []byte) error {
	if len(chunk) > chunkSize {
		panic("chunk must max 4kB")
	}
	var buf bytes.Buffer
	buf.WriteByte(chunkNum)
	buf.Write(chunk)
	buf.Write(bytes.Repeat([]byte{0xFF}, chunkSize-len(chunk)))
	_, err := device.query('w', buf.Bytes())
	return err
}

func (device *Device) flashUnsignedFirmware(firmware []byte, progressCallback func(float64)) error {
	if len(firmware) == 0 {
		return errp.New("firmware is empty")
	}
	if len(firmware) > firmwareChunks*chunkSize {
		return errp.New("firmware too big")
	}
	progressCallback(0)
	buf := bytes.NewBuffer(firmware)
	totalChunks := uint8(math.Ceil(float64(buf.Len()) / float64(chunkSize)))
	if err := device.erase(totalChunks); err != nil {
		return err
	}
	chunkNum := byte(0)
	for {
		chunk := make([]byte, chunkSize)
		readLen, err := buf.Read(chunk)
		if readLen == 0 || err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := device.writeChunk(chunkNum, chunk[:readLen]); err != nil {
			return err
		}
		chunkNum++
		progressCallback(float64(chunkNum) / float64(totalChunks))
	}
	return nil
}

// parseSignedFirmware parses a signed firmware file and returns (sigdata, firmware). Errors if the
// format is invalid, or the firmware magic does not match the expected magic according to the
// device product.
func (device *Device) parseSignedFirmware(firmware []byte) ([]byte, []byte, error) {
	product, sigData, firmware, err := ParseSignedFirmware(firmware)
	if err != nil {
		return nil, nil, err
	}
	if product != device.product {
		return nil, nil, errp.New("signed firmware binary does not match device product")
	}
	return sigData, firmware, nil
}

// SignedFirmwareVersion returns the monotonic firmware version contained in the signed firmware
// format.
func (device *Device) SignedFirmwareVersion(firmware []byte) (uint32, error) {
	sigData, _, err := device.parseSignedFirmware(firmware)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(sigData[signingPubkeysDataLen:][:4]), nil

}

func (device *Device) flashSignedFirmware(firmware []byte, progressCallback func(float64)) error {
	sigData, firmware, err := device.parseSignedFirmware(firmware)
	if err != nil {
		return err
	}
	if err := device.flashUnsignedFirmware(firmware, progressCallback); err != nil {
		return err
	}
	// write sig data
	if _, err := device.query('s', sigData); err != nil {
		return err
	}
	return nil
}

// UpgradeFirmware uploads a signed bitbox02 firmware release to the device.
func (device *Device) UpgradeFirmware(firmware []byte) error {
	return device.upgradeFirmware(func(onProgress func(float64)) error {
		return device.flashSignedFirmware(firmware, onProgress)
	})
}

// UpgradeUnsignedFirmware uploads unsigned firmware to a development device without changing
// its firmware counter or signing data, then reboots it.
func (device *Device) UpgradeUnsignedFirmware(firmware []byte) error {
	if !device.IsDevelopment() {
		return errp.New("unsigned firmware requires a development bootloader")
	}
	return device.upgradeFirmware(func(onProgress func(float64)) error {
		return device.flashUnsignedFirmware(firmware, onProgress)
	})
}

func (device *Device) upgradeFirmware(flash func(func(float64)) error) error {
	if device.status.Upgrading {
		return errp.New("already in progress")
	}
	*device.status = Status{}
	device.onStatusChanged(device.status)
	onProgress := func(progress float64) {
		device.status.Upgrading = true
		device.status.Progress = progress
		device.onStatusChanged(device.status)
	}
	err := flash(onProgress)
	if err != nil {
		device.status.Upgrading = false
		device.status.ErrMsg = err.Error()
		device.onStatusChanged(device.status)
		return err
	}
	device.status.Progress = 0
	device.status.UpgradeSuccessful = true
	device.onStatusChanged(device.status)
	return device.Reboot()
}

// Erased returns true if the device contains no firmware.
func (device *Device) Erased() (bool, error) {
	// We check by comparing the device reported firmware hash. If erased, the firmware is all
	// '\xFF'.

	return device.ContainsFirmware(nil)
}

// ContainsFirmware compares the installed firmware with an unsigned image, including erased
// padding. It uses the connected bootloader's hash format and stored firmware counter.
func (device *Device) ContainsFirmware(firmware []byte) (bool, error) {
	versions, err := device.Versions()
	if err != nil {
		return false, err
	}

	// A bootloader upgrade changes the hash scheme without changing the firmware counter.
	scheme := firmwareHashLegacy
	if device.version.AtLeast(semver.NewSemVer(1, 2, 3)) {
		scheme = firmwareHashVersioned
	} else if device.version.AtLeast(semver.NewSemVer(1, 2, 0)) {
		scheme = firmwareHashProduct
	}
	expectedFirmwareHash, err := hashFirmware(device.product, versions.FirmwareVersion, firmware, scheme)
	if err != nil {
		return false, err
	}

	firmwareHash, _, err := device.GetHashes(false, false)
	if err != nil {
		return false, err
	}
	return bytes.Equal(firmwareHash, expectedFirmwareHash), nil
}
