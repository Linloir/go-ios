package house_arrest

import (
	"bytes"
	"fmt"

	"github.com/danielpaulus/go-ios/ios/afc"
	"github.com/pkg/errors"
	"howett.net/plist"

	"github.com/danielpaulus/go-ios/ios"
)

const serviceName = "com.apple.mobile.house_arrest"

const (
	vendContainerCommand = "VendContainer"
	vendDocumentsCommand = "VendDocuments"
)

func New(device ios.DeviceEntry, bundleID string) (*afc.Client, error) {
	return NewContainer(device, bundleID)
}

// NewContainer vends the complete sandbox container. This is available for
// development-signed applications.
func NewContainer(device ios.DeviceEntry, bundleID string) (*afc.Client, error) {
	return newClient(device, bundleID, vendContainerCommand)
}

// NewDocuments vends the Documents directory. App Store and enterprise-signed
// applications expose this path when file sharing is enabled, but do not allow
// VendContainer.
func NewDocuments(device ios.DeviceEntry, bundleID string) (*afc.Client, error) {
	return newClient(device, bundleID, vendDocumentsCommand)
}

func newClient(device ios.DeviceEntry, bundleID, command string) (*afc.Client, error) {
	deviceConn, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return nil, err
	}
	err = vend(deviceConn, bundleID, command)
	if err != nil {
		_ = deviceConn.Close()
		return nil, err
	}
	return afc.NewFromConn(deviceConn), nil
}

func vend(deviceConn ios.DeviceConnectionInterface, bundleID, command string) error {
	plistCodec := ios.NewPlistCodec()
	request := buildVendRequest(bundleID, command)
	msg, err := plistCodec.Encode(request)
	if err != nil {
		return fmt.Errorf("vendContainer Encoding cannot fail unless the encoder is broken: %v", err)
	}
	err = deviceConn.Send(msg)
	if err != nil {
		return err
	}
	reader := deviceConn.Reader()
	response, err := plistCodec.Decode(reader)
	if err != nil {
		return err
	}
	return checkResponse(response)
}

func buildVendRequest(bundleID, command string) map[string]interface{} {
	return map[string]interface{}{"Command": command, "Identifier": bundleID}
}

func checkResponse(vendContainerResponseBytes []byte) error {
	response, err := plistFromBytes(vendContainerResponseBytes)
	if err != nil {
		return err
	}
	if "Complete" == response.Status {
		return nil
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return errors.New("unknown error during vendcontainer")
}

func plistFromBytes(plistBytes []byte) (vendContainerResponse, error) {
	var vendResponse vendContainerResponse
	decoder := plist.NewDecoder(bytes.NewReader(plistBytes))

	err := decoder.Decode(&vendResponse)
	if err != nil {
		return vendResponse, err
	}
	return vendResponse, nil
}

type vendContainerResponse struct {
	Status string
	Error  string
}
