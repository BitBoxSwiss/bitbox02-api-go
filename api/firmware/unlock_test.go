// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Use a locally built simulator with persistent flash to exercise a real power cycle.
// The headless simulator enters an empty password/passphrase and accepts confirmations.
func TestSimulatorUnlock(t *testing.T) {
	filename := os.Getenv("SIMULATOR")
	if filename == "" {
		t.Skip("set SIMULATOR to a locally built firmware simulator")
	}
	for _, test := range []struct {
		name             string
		enabled          bool
		requestHostEntry bool
	}{
		{name: "without-passphrase"},
		{name: "device-passphrase", enabled: true},
		{name: "device-entry-wins-host-click", enabled: true, requestHostEntry: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("FAKE_MEMORY_FILEPATH", filepath.Join(t.TempDir(), "memory"))
			stop, device, _, err := runSimulator(filename)
			require.NoError(t, err)
			t.Cleanup(func() {
				if stop != nil {
					require.NoError(t, stop())
				}
			})
			var availability []bool
			var requestHostEntry func()
			config := PassphraseConfig{
				OnHostPassphraseAvailable: func(request func()) {
					availability = append(availability, request != nil)
					if request != nil {
						requestHostEntry = request
						if test.requestHostEntry {
							request()
						}
					}
				},
				EnterMnemonicPassphrase: func(context.Context) (*string, error) {
					t.Error("host input must not be requested without host-entry consent")
					return nil, nil
				},
			}
			device.options.passphrase = config
			require.NoError(t, device.Init())
			device.ChannelHashVerify(true)
			require.Equal(t, StatusUninitialized, device.Status())
			require.NoError(t, device.RestoreFromMnemonic())
			require.NoError(t, device.SetMnemonicPassphraseEnabled(test.enabled))
			require.NoError(t, stop())
			stop = nil

			// Restarting preserves flash but clears the unlocked seed and Noise session.
			var stdout *simulatorStdout
			stop, device, stdout, err = runSimulator(filename)
			require.NoError(t, err)
			device.options.passphrase = config
			entered := 0
			device.SetOnEvent(func(event Event, _ interface{}) {
				if event == EventPassphraseEntered {
					entered++
				}
			})
			require.NoError(t, device.Init())
			device.ChannelHashVerify(true)
			require.Equal(t, StatusInitialized, device.Status())
			fp, err := device.RootFingerprint()
			require.NoError(t, err)
			require.Equal(t, "4c00739d", hex.EncodeToString(fp))
			if test.enabled {
				require.Contains(t, stdout.String(), "Optional passphrase")
			} else {
				require.NotContains(t, stdout.String(), "Optional passphrase")
			}
			if device.supportsPairedUnlock() {
				if test.enabled {
					require.Equal(t, []bool{true, false}, availability)
					require.Equal(t, 1, entered)
					// A delayed click from the completed phase must have no effect.
					requestHostEntry()
				} else {
					require.Empty(t, availability)
					require.Zero(t, entered)
				}
				checkpoint := stdout.checkpoint()
				// Duplicate pairing approvals and unlocks must not open another passphrase flow.
				device.ChannelHashVerify(true)
				enteredBefore := entered
				require.NoError(t, device.unlock())
				require.Equal(t, enteredBefore, entered)
				output, err := stdout.snapshot(checkpoint)
				require.NoError(t, err)
				require.NotContains(t, output, "Optional passphrase")
				fpAfter, err := device.RootFingerprint()
				require.NoError(t, err)
				require.Equal(t, fp, fpAfter)
			} else {
				require.Empty(t, availability)
				require.Zero(t, entered)
			}
			// A disconnect and an interrupted workflow can both close the real transport.
			device.Close()
			device.Close()
		})
	}
}
