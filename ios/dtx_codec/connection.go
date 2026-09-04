package dtx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios"

	"github.com/danielpaulus/go-ios/ios/nskeyedarchiver"
	log "github.com/sirupsen/logrus"
)

type MethodWithResponse func(msg Message) (interface{}, error)

var ErrConnectionClosed = errors.New("Connection closed")

// Connection manages channels, including the GlobalChannel, for a DtxConnection and dispatches received messages
// to the right channel.
type Connection struct {
	deviceConnection       ios.DeviceConnectionInterface
	channelCodeCounter     int
	activeChannels         sync.Map
	globalChannel          *Channel
	capabilities           map[string]interface{}
	mutex                  sync.Mutex
	sendMu                 sync.Mutex
	requestChannelMessages chan Message

	// MessageDispatcher use this prop to catch messages from GlobalDispatcher
	// and handle it accordingly in a custom dispatcher of the dedicated service
	//
	// Set this prop when creating a connection instance
	//
	// Refer to end-to-end example of `instruments/instruments_sysmontap.go`
	MessageDispatcher Dispatcher

	closed    chan struct{}
	errMu     sync.RWMutex
	err       error
	closeOnce sync.Once

	deviceCloseOnce sync.Once
	deviceCloseErr  error
}

// Dispatcher is a simple interface containing a Dispatch func to receive dtx.Messages
type Dispatcher interface {
	Dispatch(msg Message)
}

// GlobalDispatcher the message dispatcher for the automatically created global Channel
type GlobalDispatcher struct {
	dispatchFunctions      map[string]func(Message)
	requestChannelMessages chan Message
	dtxConnection          *Connection
}

const requestChannel = "_requestChannelWithCode:identifier:"

// Closed is closed when the underlying DTX connection was closed for any reason (either initiated by calling Close() or due to an error)
func (dtxConn *Connection) Closed() <-chan struct{} {
	return dtxConn.closed
}

// Err is non-nil when the connection was closed (when Close was called this will be ErrConnectionClosed)
func (dtxConn *Connection) Err() error {
	dtxConn.errMu.RLock()
	defer dtxConn.errMu.RUnlock()
	return dtxConn.err
}

// Close closes the underlying deviceConnection
func (dtxConn *Connection) Close() error {
	dtxConn.close(ErrConnectionClosed)
	return dtxConn.closeDeviceConnection()
}

func (dtxConn *Connection) closeDeviceConnection() error {
	dtxConn.deviceCloseOnce.Do(func() {
		if dtxConn.deviceConnection != nil {
			dtxConn.deviceCloseErr = dtxConn.deviceConnection.Close()
		}
	})
	return dtxConn.deviceCloseErr
}

// GlobalChannel returns the connections automatically created global channel.
func (dtxConn *Connection) GlobalChannel() *Channel {
	return dtxConn.globalChannel
}

// NewGlobalDispatcher create a Dispatcher for the GlobalChannel
func NewGlobalDispatcher(requestChannelMessages chan Message, dtxConnection *Connection) Dispatcher {
	dispatcher := GlobalDispatcher{
		dispatchFunctions:      map[string]func(Message){},
		requestChannelMessages: requestChannelMessages,
		dtxConnection:          dtxConnection,
	}
	const notifyPublishedCaps = "_notifyOfPublishedCapabilities:"
	dispatcher.dispatchFunctions[notifyPublishedCaps] = notifyOfPublishedCapabilities
	return dispatcher
}

// Dispatch to a MessageDispatcher of the Connection if set
func (dtxConn *Connection) Dispatch(msg Message) {
	msgDispatcher := dtxConn.MessageDispatcher
	if msgDispatcher != nil {
		log.Debugf("msg dispatcher found: %T", msgDispatcher)
		msgDispatcher.Dispatch(msg)
		return
	}

	log.Errorf("no connection dispatcher registered for global channel, msg: %v", msg)
}

// Dispatch prints log messages and errors when they are received and also creates local Channels when requested by the device.
func (g GlobalDispatcher) Dispatch(msg Message) {
	SendAckIfNeeded(g.dtxConnection, msg)
	if len(msg.Payload) > 0 {
		if requestChannel == msg.Payload[0] {
			select {
			case g.requestChannelMessages <- msg:
			default:
				log.Warn("dropping DTX channel request because the request queue is full")
			}
		}
		// TODO: use the dispatchFunctions map
		if "outputReceived:fromProcess:atTime:" == msg.Payload[0] {
			args := msg.Auxiliary.GetArguments()
			if len(args) < 3 {
				log.Warnf("outputReceived:fromProcess:atTime: expected at least 3 arguments, got %d", len(args))
				return
			}
			logBytes, ok := args[0].([]byte)
			if !ok {
				log.Warnf("outputReceived:fromProcess:atTime: expected []byte argument, got %T", args[0])
				return
			}
			logmsg, err := nskeyedarchiver.Unarchive(logBytes)
			if err == nil {
				log.WithFields(log.Fields{
					"msg":  logmsg[0],
					"pid":  args[1],
					"time": args[2],
				}).Debug("outputReceived:fromProcess:atTime:")
			}
			return
		}
	}
	log.Tracef("Global Dispatcher Received: %s %s", msg.Payload, msg.Auxiliary)
	if msg.HasError() {
		log.Error(msg.Payload)
	}
	if msg.PayloadHeader.MessageType == UnknownTypeOne || msg.PayloadHeader.MessageType == ResponseWithReturnValueInPayload {
		g.dtxConnection.Dispatch(msg)
	}
}

func notifyOfPublishedCapabilities(msg Message) {
	log.Debug("capabs received")
}

// NewUsbmuxdConnection connects and starts reading from a Dtx based service on the device
func NewUsbmuxdConnection(device ios.DeviceEntry, serviceName string) (*Connection, error) {
	conn, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return nil, err
	}

	return newDtxConnection(conn)
}

// NewUsbmuxdConnectionWithDispatcher installs the global message dispatcher
// before the reader goroutine starts. This prevents the first service event
// from racing a dispatcher assignment performed after construction.
func NewUsbmuxdConnectionWithDispatcher(device ios.DeviceEntry, serviceName string, dispatcher Dispatcher) (*Connection, error) {
	conn, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return nil, err
	}

	return newDtxConnection(conn, dispatcher)
}

// NewTunnelConnection connects and starts reading from a Dtx based service on the device, using tunnel interface instead of usbmuxd
func NewTunnelConnection(device ios.DeviceEntry, serviceName string) (*Connection, error) {
	conn, err := ios.ConnectToServiceTunnelIface(device, serviceName)
	if err != nil {
		return nil, err
	}

	return newDtxConnection(conn)
}

// NewTunnelConnectionWithDispatcher is the tunnel equivalent of
// NewUsbmuxdConnectionWithDispatcher.
func NewTunnelConnectionWithDispatcher(device ios.DeviceEntry, serviceName string, dispatcher Dispatcher) (*Connection, error) {
	conn, err := ios.ConnectToServiceTunnelIface(device, serviceName)
	if err != nil {
		return nil, err
	}

	return newDtxConnection(conn, dispatcher)
}

func newDtxConnection(conn ios.DeviceConnectionInterface, messageDispatchers ...Dispatcher) (*Connection, error) {
	requestChannelMessages := make(chan Message, 5)
	var messageDispatcher Dispatcher
	if len(messageDispatchers) > 0 {
		messageDispatcher = messageDispatchers[0]
	}

	// The global channel has channelCode 0, so we need to start with channelCodeCounter==1
	dtxConnection := &Connection{
		deviceConnection:       conn,
		channelCodeCounter:     1,
		requestChannelMessages: requestChannelMessages,
		MessageDispatcher:      messageDispatcher,
	}
	dtxConnection.closed = make(chan struct{})

	// The global channel is automatically present and used for requesting other channels and some other methods like notifyPublishedCapabilities
	globalChannel := Channel{
		channelCode:       0,
		messageIdentifier: 5, channelName: "global_channel", connection: dtxConnection,
		messageDispatcher: NewGlobalDispatcher(requestChannelMessages, dtxConnection),
		responseWaiters:   map[int]chan Message{},
		registeredMethods: map[string]chan Message{},
		defragmenters:     map[int]*FragmentDecoder{},
		timeout:           5 * time.Second,
	}
	dtxConnection.globalChannel = &globalChannel
	go reader(dtxConnection)

	return dtxConnection, nil
}

// Send sends the byte slice directly to the device using the underlying DeviceConnectionInterface
func (dtxConn *Connection) Send(message []byte) error {
	if dtxConn == nil || dtxConn.deviceConnection == nil {
		return ErrConnectionClosed
	}
	dtxConn.sendMu.Lock()
	defer dtxConn.sendMu.Unlock()
	select {
	case <-dtxConn.closed:
		if err := dtxConn.Err(); err != nil {
			return err
		}
		return ErrConnectionClosed
	default:
	}

	written := 0
	for written < len(message) {
		n, err := dtxConn.deviceConnection.Writer().Write(message[written:])
		if n < 0 || n > len(message)-written {
			err = fmt.Errorf("invalid DTX write count %d", n)
		}
		written += n
		if err != nil {
			dtxConn.close(err)
			_ = dtxConn.closeDeviceConnection()
			return err
		}
		if n == 0 {
			err = io.ErrShortWrite
			dtxConn.close(err)
			_ = dtxConn.closeDeviceConnection()
			return err
		}
	}
	return nil
}

// reader reads messages from the byte stream and dispatches them to the right channel when they are decoded.
func reader(dtxConn *Connection) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("DTX reader panic: %v", recovered)
			dtxConn.close(err)
			_ = dtxConn.closeDeviceConnection()
			log.WithFields(log.Fields{"error": err, "stack": string(debug.Stack())}).Error("DTX reader stopped after panic")
		}
	}()
	reader := bufio.NewReader(dtxConn.deviceConnection.Reader())
	for {
		msg, err := ReadMessage(reader)
		if err != nil {
			dtxConn.close(err)
			// A peer-side EOF used to signal Closed without releasing the local
			// transport. Close it here as well so callers waiting on Closed (or
			// callers that fail to run their own cleanup) cannot strand an fd.
			_ = dtxConn.closeDeviceConnection()
			errText := err.Error()
			if err == io.EOF || strings.Contains(errText, "use of closed network") {
				log.Debug("DTX Connection with EOF")
				return
			}
			log.Errorf("error reading dtx connection %+v", err)
			return
		}
		if _channel, ok := dtxConn.activeChannels.Load(msg.ChannelCode); ok {
			channel := _channel.(*Channel)
			channel.Dispatch(msg)
		} else {
			dtxConn.globalChannel.Dispatch(msg)
		}
	}
}

func SendAckIfNeeded(dtxConn *Connection, msg Message) {
	if msg.ExpectsReply && dtxConn != nil {
		ack := BuildAckMessage(msg)
		err := dtxConn.Send(ack)
		if err != nil {
			log.Errorf("Error sending ack:%s", err)
		}
	}
}

func (dtxConn *Connection) ForChannelRequest(messageDispatcher Dispatcher) *Channel {
	channel, err := dtxConn.ForChannelRequestContext(context.Background(), messageDispatcher)
	if err != nil {
		log.WithError(err).Error("failed waiting for DTX channel request")
		return nil
	}
	return channel
}

// ForChannelRequestContext waits for a device-initiated DTX channel request.
// It stops waiting when the caller cancels or the underlying connection closes.
func (dtxConn *Connection) ForChannelRequestContext(ctx context.Context, messageDispatcher Dispatcher) (*Channel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-dtxConn.closed:
		if err := dtxConn.Err(); err != nil {
			return nil, err
		}
		return nil, ErrConnectionClosed
	default:
	}

	var msg Message
	select {
	case msg = <-dtxConn.requestChannelMessages:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-dtxConn.closed:
		if err := dtxConn.Err(); err != nil {
			return nil, err
		}
		return nil, ErrConnectionClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-dtxConn.closed:
		if err := dtxConn.Err(); err != nil {
			return nil, err
		}
		return nil, ErrConnectionClosed
	default:
	}

	dtxConn.mutex.Lock()
	defer dtxConn.mutex.Unlock()
	// code := msg.Auxiliary.GetArguments()[0].(uint32)
	arguments := msg.Auxiliary.GetArguments()
	if len(arguments) < 2 {
		return nil, fmt.Errorf("DTX channel request has %d arguments, expected at least 2", len(arguments))
	}
	identifierBytes, ok := arguments[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("DTX channel request identifier has type %T, expected []byte", arguments[1])
	}
	identifier, err := nskeyedarchiver.Unarchive(identifierBytes)
	if err != nil {
		return nil, fmt.Errorf("decode DTX channel request identifier: %w", err)
	}
	if len(identifier) == 0 {
		return nil, errors.New("DTX channel request has an empty identifier")
	}
	channelName, ok := identifier[0].(string)
	if !ok {
		return nil, fmt.Errorf("DTX channel request identifier has type %T, expected string", identifier[0])
	}
	// TODO: Setting the channel code here manually to -1 for making testmanagerd work. For some reason it requests the TestDriver proxy channel with code 1 but sends messages on -1. Should probably be fixed somehow
	// TODO: try to refactor testmanagerd/xcuitest code and use AddDefaultChannelReceiver instead of this function. The only code calling this is in testmanagerd right now.
	channel := &Channel{channelCode: -1, channelName: channelName, messageIdentifier: 1, connection: dtxConn, messageDispatcher: messageDispatcher, responseWaiters: map[int]chan Message{}, defragmenters: map[int]*FragmentDecoder{}, timeout: 5 * time.Second}
	dtxConn.activeChannels.Store(-1, channel)
	return channel, nil
}

// AddDefaultChannelReceiver let's you set the Dispatcher for the Channel with code -1 ( or 4294967295 for uint32).
// I am just calling it the "default" channel now, without actually figuring out what it is for exactly from disassembled code.
// If someone wants to do that and bring some clarity, please go ahead :-)
// This channel seems to always be there without explicitly requesting it and sometimes it is used.
func (dtxConn *Connection) AddDefaultChannelReceiver(messageDispatcher Dispatcher) *Channel {
	channel := &Channel{channelCode: -1, channelName: "c -1/ 4294967295 receiver channel ", messageIdentifier: 1, connection: dtxConn, messageDispatcher: messageDispatcher, responseWaiters: map[int]chan Message{}, defragmenters: map[int]*FragmentDecoder{}, timeout: 5 * time.Second}
	dtxConn.activeChannels.Store(-1, channel)
	return channel
}

// RequestChannelIdentifier requests a channel to be opened on the Connection with the given identifier,
// an automatically assigned channelCode and a Dispatcher for receiving messages.
func (dtxConn *Connection) RequestChannelIdentifier(identifier string, messageDispatcher Dispatcher, opts ...ChannelOption) *Channel {
	channel, err := dtxConn.RequestChannelIdentifierWithError(identifier, messageDispatcher, opts...)
	if err != nil {
		log.WithFields(log.Fields{"channel_id": identifier, "error": err}).Error("failed requesting channel")
		return nil
	}
	return channel
}

// RequestChannelIdentifierWithError requests a channel and reports handshake
// failures to the caller. RequestChannelIdentifier is retained for API
// compatibility, but returns nil rather than a channel that was never opened.
func (dtxConn *Connection) RequestChannelIdentifierWithError(identifier string, messageDispatcher Dispatcher, opts ...ChannelOption) (*Channel, error) {
	dtxConn.mutex.Lock()
	defer dtxConn.mutex.Unlock()
	code := dtxConn.channelCodeCounter
	dtxConn.channelCodeCounter++

	payload, err := nskeyedarchiver.ArchiveBin(requestChannel)
	if err != nil {
		return nil, fmt.Errorf("encode DTX channel request selector: %w", err)
	}
	auxiliary := NewPrimitiveDictionary()
	auxiliary.AddInt32(code)
	arch, err := nskeyedarchiver.ArchiveBin(identifier)
	if err != nil {
		return nil, fmt.Errorf("encode DTX channel identifier %q: %w", identifier, err)
	}
	auxiliary.AddBytes(arch)
	log.WithFields(log.Fields{"channel_id": identifier}).Debug("Requesting channel")
	channel := &Channel{channelCode: code, channelName: identifier, messageIdentifier: 1, connection: dtxConn, messageDispatcher: messageDispatcher, responseWaiters: map[int]chan Message{}, defragmenters: map[int]*FragmentDecoder{}, timeout: 5 * time.Second}
	for _, opt := range opts {
		opt(channel)
	}
	// Publish the channel before requesting it. The device may send the first
	// event immediately after its ACK, before sendAndAwaitReply returns.
	dtxConn.activeChannels.Store(code, channel)

	ctx, cancel := context.WithTimeout(context.Background(), dtxConn.globalChannel.timeout)
	defer cancel()
	rply, err := dtxConn.globalChannel.sendAndAwaitReply(ctx, true, Methodinvocation, payload, auxiliary)
	log.Debug(rply)
	if err != nil {
		dtxConn.activeChannels.Delete(code)
		return nil, fmt.Errorf("request DTX channel %q: %w", identifier, err)
	}
	log.WithFields(log.Fields{"channel_id": identifier}).Debug("Channel open")

	return channel, nil
}

func (dtxConn *Connection) close(err error) {
	dtxConn.closeOnce.Do(func() {
		dtxConn.errMu.Lock()
		dtxConn.err = err
		dtxConn.errMu.Unlock()
		close(dtxConn.closed)
	})
}
