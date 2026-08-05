package afc

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsObjectNotFound(t *testing.T) {
	missing := fmt.Errorf("stat failed: %w", afcError{code: errObjectNotFound})
	if !IsObjectNotFound(missing) {
		t.Fatal("wrapped ObjectNotFound was not recognized")
	}
	if IsObjectNotFound(afcError{code: errPermDenied}) {
		t.Fatal("permission error was recognized as ObjectNotFound")
	}
	if IsObjectNotFound(errors.New("ObjectNotFound")) {
		t.Fatal("text-only error was recognized as an AFC status")
	}
}
