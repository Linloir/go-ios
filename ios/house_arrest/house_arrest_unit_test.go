package house_arrest

import "testing"

func TestBuildVendRequest(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "container", command: vendContainerCommand},
		{name: "documents", command: vendDocumentsCommand},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := buildVendRequest("com.example.app", test.command)
			if got := request["Command"]; got != test.command {
				t.Fatalf("Command = %#v, want %q", got, test.command)
			}
			if got := request["Identifier"]; got != "com.example.app" {
				t.Fatalf("Identifier = %#v", got)
			}
		})
	}
}
