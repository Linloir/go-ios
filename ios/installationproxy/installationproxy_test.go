package installationproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildInstallCommand(t *testing.T) {
	options := map[string]interface{}{
		"ApplicationType": "User",
		"PackageType":     "Developer",
	}
	command := buildInstallCommand("PublicStaging/Test.ipa", options)

	assert.Equal(t, "Install", command["Command"])
	assert.Equal(t, "PublicStaging/Test.ipa", command["PackagePath"])
	assert.Equal(t, options, command["ClientOptions"])
}

func TestCheckFinished(t *testing.T) {
	done, err := checkFinished(map[string]interface{}{"Status": "Installing"})
	require.NoError(t, err)
	assert.False(t, done)

	done, err = checkFinished(map[string]interface{}{"Status": "Complete"})
	require.NoError(t, err)
	assert.True(t, done)

	done, err = checkFinished(map[string]interface{}{
		"Error":            "ApplicationVerificationFailed",
		"ErrorDescription": "signature is invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
	assert.True(t, done)
}
