package appservice

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSendSignalPayload(t *testing.T) {
	payload := buildSendSignalPayload("device-id", 1234, syscall.SIGTERM)

	assert.Equal(t, "device-id", payload["CoreDevice.deviceIdentifier"])
	assert.Equal(t, "com.apple.coredevice.feature.sendsignaltoprocess", payload["CoreDevice.featureIdentifier"])
	input, ok := payload["CoreDevice.input"].(map[string]interface{})
	require.True(t, ok)
	process, ok := input["process"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, int64(1234), process["processIdentifier"])
	assert.Equal(t, int64(syscall.SIGTERM), input["signal"])
}
