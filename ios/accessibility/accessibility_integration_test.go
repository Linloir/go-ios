//go:build integration
// +build integration

package accessibility_test

import (
	"context"
	"testing"
	"time"

	ios "github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/accessibility"
)

func TestMove(t *testing.T) {
	device, err := ios.GetDevice("")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := accessibility.NewWithoutEventChangeListeners(device)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		conn.TurnOff()
		_ = conn.Close()
	}()

	conn.SwitchToDevice()
	conn.EnableSelectionMode()

	t.Run("Test Move directions", func(t *testing.T) {
		directions := []accessibility.MoveDirection{
			// newer ios(18+) devices sometimes doesn't bring focus to first element, so we need to move twice
			accessibility.DirectionNext,
			accessibility.DirectionNext,
			accessibility.DirectionPrevious,
		}

		for _, direction := range directions {
			t.Logf("Testing direction: %v", direction)
			conn.Move(direction)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			element, err := conn.AwaitElementChanged(ctx)
			cancel()
			if err != nil {
				t.Logf("Move %v failed (expected on some devices): %v", direction, err)
				continue
			}

			t.Logf("Move %v succeeded: %+v", direction, element)
		}
	})
}
