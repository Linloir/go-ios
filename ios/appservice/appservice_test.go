package appservice

import (
	"syscall"
	"testing"

	"github.com/google/uuid"
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

func TestBuildAppLaunchPayloadMatchesIOSKitOptions(t *testing.T) {
	payload := buildAppLaunchPayload("device-id", "com.example.app", nil, nil, nil, true, nil)
	input, ok := payload["CoreDevice.input"].(map[string]interface{})
	require.True(t, ok)
	options, ok := input["options"].(map[string]interface{})
	require.True(t, ok)

	_, hasWorkingDirectory := options["workingDirectory"]
	assert.False(t, hasWorkingDirectory)
	terminationHandler, ok := options["terminationHandler"].(map[string]interface{})
	require.True(t, ok)
	sideChannel, ok := terminationHandler["sideChannel"].(uuid.UUID)
	require.True(t, ok)
	assert.NotEqual(t, uuid.Nil, sideChannel)
}
