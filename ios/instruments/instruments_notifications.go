package instruments

import (
	"fmt"
	"io"
	"sync"

	"github.com/danielpaulus/go-ios/ios"
	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
	log "github.com/sirupsen/logrus"
)

type channelDispatcher struct {
	messageChannel   chan dtx.Message
	closeChannel     chan struct{}
	connection       io.Closer
	dtxConnection    *dtx.Connection
	connectionClosed <-chan struct{}
	connectionErr    func() error
	closeOnce        sync.Once
	closeErr         error
}

func ListenAppStateNotifications(device ios.DeviceEntry) (func() (map[string]interface{}, error), func() error, error) {
	conn, err := connectInstruments(device)
	if err != nil {
		return nil, nil, err
	}
	dispatcher := &channelDispatcher{
		messageChannel:   make(chan dtx.Message, 32),
		closeChannel:     make(chan struct{}),
		connection:       conn,
		dtxConnection:    conn,
		connectionClosed: conn.Closed(),
		connectionErr:    conn.Err,
	}
	conn.AddDefaultChannelReceiver(dispatcher)
	channel, err := conn.RequestChannelIdentifierWithError(mobileNotificationsChannel, dispatcher)
	if err != nil {
		_ = dispatcher.Close()
		return nil, nil, fmt.Errorf("request mobile notifications channel: %w", err)
	}
	resp, err := channel.MethodCall("setApplicationStateNotificationsEnabled:", true)
	if err != nil {
		_ = dispatcher.Close()
		log.Errorf("enable application state notifications: resp=%+v err=%v", resp, err)
		return nil, nil, err
	}
	log.Debugf("appstatenotifications enabled successfully: %+v", resp)
	resp, err = channel.MethodCall("setMemoryNotificationsEnabled:", true)
	if err != nil {
		_ = dispatcher.Close()
		log.Errorf("enable memory notifications: resp=%+v err=%v", resp, err)
		return nil, nil, err
	}
	log.Debugf("memory notifications enabled: %+v", resp)

	return dispatcher.Receive, dispatcher.Close, nil
}

func (dispatcher *channelDispatcher) Receive() (map[string]interface{}, error) {
	for {
		select {
		case msg := <-dispatcher.messageChannel:
			selector, result, err := toMap(msg)
			if "applicationStateNotification:" == selector && err == nil {
				return result, nil
			}
			if err != nil {
				log.Debugf("error extracting message %+v, %v", msg, err)
			}
		case <-dispatcher.closeChannel:
			return map[string]interface{}{}, io.EOF
		case <-dispatcher.connectionClosed:
			err := io.EOF
			if dispatcher.connectionErr != nil && dispatcher.connectionErr() != nil {
				err = dispatcher.connectionErr()
			}
			return map[string]interface{}{}, err
		}
	}
}

func (dispatcher *channelDispatcher) Close() error {
	if dispatcher == nil {
		return nil
	}
	dispatcher.closeOnce.Do(func() {
		close(dispatcher.closeChannel)
		if dispatcher.connection != nil {
			dispatcher.closeErr = dispatcher.connection.Close()
		}
	})
	return dispatcher.closeErr
}

func (dispatcher *channelDispatcher) Dispatch(msg dtx.Message) {
	dtx.SendAckIfNeeded(dispatcher.dtxConnection, msg)
	// Never stall the single DTX reader behind a slow notification consumer.
	// Application state is edge-triggered but the newest state is the useful
	// one, so discard the oldest queued event when the bounded queue is full.
	select {
	case dispatcher.messageChannel <- msg:
		return
	case <-dispatcher.closeChannel:
		return
	default:
	}
	select {
	case <-dispatcher.messageChannel:
	default:
	}
	select {
	case dispatcher.messageChannel <- msg:
	case <-dispatcher.closeChannel:
	default:
	}
}
