package instruments

import (
	"fmt"

	"github.com/danielpaulus/go-ios/ios"
	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
)

const locationSimulationIdentifier = "com.apple.instruments.server.services.LocationSimulation"

// LocationSimulationService gives us access to simulate device geo location
type LocationSimulationService struct {
	channel *dtx.Channel
	conn    *dtx.Connection
}

// StartSimulateLocation sets geolocation with provided params
func (d *LocationSimulationService) StartSimulateLocation(lat, lon float64) error {
	_, err := d.channel.MethodCall("simulateLocationWithLatitude:longitude:", lat, lon)
	if err != nil {
		return err
	}

	return nil
}

// StopSimulateLocation clears simulated location
func (d *LocationSimulationService) StopSimulateLocation() error {
	defer d.Close()
	_, err := d.channel.MethodCall("stopLocationSimulation")
	if err != nil {
		return err
	}

	return nil
}

// NewLocationSimulationService creates a new LocationSimulationService for a given device
func NewLocationSimulationService(device ios.DeviceEntry) (*LocationSimulationService, error) {
	dtxConn, err := connectInstruments(device)
	if err != nil {
		return nil, err
	}
	processControlChannel, err := dtxConn.RequestChannelIdentifierWithError(locationSimulationIdentifier, loggingDispatcher{dtxConn})
	if err != nil {
		_ = dtxConn.Close()
		return nil, fmt.Errorf("request location simulation channel: %w", err)
	}
	return &LocationSimulationService{channel: processControlChannel, conn: dtxConn}, nil
}

// Close closes up the DTX connection
func (d *LocationSimulationService) Close() {
	d.conn.Close()
}
