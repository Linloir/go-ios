package instruments

import (
	"fmt"

	"github.com/danielpaulus/go-ios/ios"
	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
	log "github.com/sirupsen/logrus"
)

type metricsDispatcher struct {
	messageChannel chan dtx.Message
	closeChannel   chan struct{}
}

func (dispatcher metricsDispatcher) Dispatch(msg dtx.Message) {
	log.Infof("%+v", msg)
}

func GetMetrics(device ios.DeviceEntry) (func() (map[string]interface{}, error), func() error, error) {
	conn, err := connectInstruments(device)
	if err != nil {
		return nil, nil, err
	}
	// This experimental API does not currently return a usable receiver or
	// closer. Do not strand an Instruments/DTX connection while it remains
	// incomplete.
	defer conn.Close()
	dispatcher := metricsDispatcher{messageChannel: make(chan dtx.Message), closeChannel: make(chan struct{})}
	conn.AddDefaultChannelReceiver(dispatcher)
	channel, err := conn.RequestChannelIdentifierWithError(mobileNotificationsChannel, loggingDispatcher{conn})
	if err != nil {
		return nil, nil, fmt.Errorf("request mobile notifications channel: %w", err)
	}
	resp, err := channel.MethodCall("setApplicationStateNotificationsEnabled:", true)
	if err != nil {
		log.Errorf("enable application state notifications: resp=%+v err=%v", resp, err)
		return nil, nil, err
	}
	log.Debugf("appstatenotifications enabled successfully: %+v", resp)
	resp, err = channel.MethodCall("setMemoryNotificationsEnabled:", true)
	if err != nil {
		log.Errorf("enable memory notifications: resp=%+v err=%v", resp, err)
		return nil, nil, err
	}
	log.Debugf("memory notifications enabled: %+v", resp)

	return nil, nil, nil
}
