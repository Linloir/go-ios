package instruments

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapToProcInfoBundleIdentifier(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"isApplication": true,
			"name":          "Example",
			"pid":           uint64(42),
			"realAppName":   "/private/var/containers/Bundle/Application/Example.app/Example",
		}
	}

	t.Run("present", func(t *testing.T) {
		process := base()
		process["bundleIdentifier"] = "com.example.app"
		got := mapToProcInfo([]interface{}{process})
		assert.Equal(t, "com.example.app", got[0].BundleIdentifier)
	})

	t.Run("missing", func(t *testing.T) {
		got := mapToProcInfo([]interface{}{base()})
		assert.Empty(t, got[0].BundleIdentifier)
	})

	t.Run("wrong type", func(t *testing.T) {
		process := base()
		process["bundleIdentifier"] = uint64(1)
		got := mapToProcInfo([]interface{}{process})
		assert.Empty(t, got[0].BundleIdentifier)
	})
}
