package dtx

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios/nskeyedarchiver"
	log "github.com/sirupsen/logrus"
)

type Channel struct {
	channelCode       int
	channelName       string
	messageIdentifier int
	connection        *Connection
	messageDispatcher Dispatcher
	responseWaiters   map[int]chan Message
	defragmenters     map[int]*FragmentDecoder
	registeredMethods map[string]chan Message
	mutex             sync.Mutex
	timeout           time.Duration
}

const (
	fragmentAssemblyTTL                   = time.Minute
	maxDTXFragmentAssembliesPerChannel    = 128
	maxDTXFragmentCacheBytesPerChannel    = 256 << 20
	fragmentAssemblyMetadataBytesPerPiece = 256
)

// ChannelOption for configuring settings on dtx.Channels
type ChannelOption func(*Channel)

// WithTimeout adds a custom timeout in seconds to the channel.
// Some longer running synchronous operations need that.
func WithTimeout(seconds uint32) ChannelOption {
	return func(h *Channel) {
		h.timeout = time.Duration(seconds) * time.Second
	}
}

func (d *Channel) RegisterMethodForRemote(selector string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.registeredMethods == nil {
		d.registeredMethods = make(map[string]chan Message)
	}
	d.registeredMethods[selector] = make(chan Message, 8)
}

func (d *Channel) ReceiveMethodCall(selector string) Message {
	d.mutex.Lock()
	channel := d.registeredMethods[selector]
	d.mutex.Unlock()
	select {
	case msg := <-channel:
		return msg
	case <-d.connection.Closed():
		return Message{}
	}
}

func (d *Channel) ReceiveMethodCallWithTimeout(ctx context.Context, selector string) (Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	d.mutex.Lock()
	channel := d.registeredMethods[selector]
	d.mutex.Unlock()
	select {
	case msg := <-channel:
		return msg, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-d.connection.Closed():
		err := d.connection.Err()
		if err == nil {
			err = ErrConnectionClosed
		}
		return Message{}, err
	}
}

// MethodCall is the standard DTX style remote method invocation pattern. The ObjectiveC Selector goes as a NSKeyedArchiver.archived NSString into the
// DTXMessage payload, and the arguments are separately NSKeyArchiver.archived and put into the Auxiliary DTXPrimitiveDictionary. It returns the response message and an error.
// Always uses the channel's default timeout.
func (d *Channel) MethodCall(selector string, args ...interface{}) (Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.MethodCallWithContext(ctx, selector, args...)
}

// MethodCallWithContext is like MethodCall but respects the provided context for cancellation/timeout.
// If the context has no deadline, the channel's default timeout is applied.
func (d *Channel) MethodCallWithContext(ctx context.Context, selector string, args ...interface{}) (Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	auxiliary := NewPrimitiveDictionary()
	for _, arg := range args {
		auxiliary.AddNsKeyedArchivedObject(arg)
	}

	return d.methodCallWithReply(ctx, selector, auxiliary)
}

// MethodCallWithAuxiliary is a DTX style remote method invocation pattern. The ObjectiveC Selector goes as a NSKeyedArchiver.archived NSString into the
// DTXMessage payload, and the primitive arguments put into the Auxiliary DTXPrimitiveDictionary. It returns the response message and an error.
func (d *Channel) MethodCallWithAuxiliary(selector string, aux PrimitiveDictionary) (Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.methodCallWithReply(ctx, selector, aux)
}

func (d *Channel) methodCallWithReply(ctx context.Context, selector string, auxiliary PrimitiveDictionary) (Message, error) {
	payload, _ := nskeyedarchiver.ArchiveBin(selector)
	msg, err := d.sendAndAwaitReply(ctx, true, Methodinvocation, payload, auxiliary)
	if err != nil {
		log.WithFields(log.Fields{"channel_id": d.channelName, "error": err, "methodselector": selector}).Info("failed starting invoking method")
		return msg, err
	}
	if msg.HasError() {
		return msg, fmt.Errorf("failed invoking method '%s' with error: %v", selector, msg.Payload)
	}
	return msg, nil
}

func (d *Channel) MethodCallAsync(selector string, args ...interface{}) error {
	payload, _ := nskeyedarchiver.ArchiveBin(selector)
	auxiliary := NewPrimitiveDictionary()
	for _, arg := range args {
		auxiliary.AddNsKeyedArchivedObject(arg)
	}
	err := d.Send(false, Methodinvocation, payload, auxiliary)
	if err != nil {
		log.WithFields(log.Fields{"channel_id": d.channelName, "error": err, "methodselector": selector}).Info("failed starting invoking method")
		return err
	}
	return nil
}

func (d *Channel) Send(expectsReply bool, messageType MessageType, payloadBytes []byte, auxiliary PrimitiveDictionary) error {
	d.mutex.Lock()

	identifier := d.messageIdentifier
	d.messageIdentifier++
	d.mutex.Unlock()

	bytes, err := Encode(identifier, 0, d.channelCode, expectsReply, messageType, payloadBytes, auxiliary)
	if err != nil {
		return err
	}
	return d.connection.Send(bytes)
}

func (d *Channel) AddResponseWaiter(identifier int, channel chan Message) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.responseWaiters[identifier] = channel
}

func (d *Channel) removeResponseWaiter(identifier int) {
	d.mutex.Lock()
	delete(d.responseWaiters, identifier)
	delete(d.defragmenters, identifier)
	d.mutex.Unlock()
}

func (d *Channel) takeResponseWaiter(identifier int) chan Message {
	d.mutex.Lock()
	channel := d.responseWaiters[identifier]
	delete(d.responseWaiters, identifier)
	d.mutex.Unlock()
	return channel
}

func (d *Channel) sendAndAwaitReply(ctx context.Context, expectsReply bool, messageType MessageType, payloadBytes []byte, auxiliary PrimitiveDictionary) (Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Message{}, err
	}
	select {
	case <-d.connection.Closed():
		err := d.connection.Err()
		if err == nil {
			err = ErrConnectionClosed
		}
		return Message{}, err
	default:
	}

	d.mutex.Lock()
	identifier := d.messageIdentifier
	d.messageIdentifier++
	d.mutex.Unlock()
	bytes, err := Encode(identifier, 0, d.channelCode, expectsReply, messageType, payloadBytes, auxiliary)
	if err != nil {
		return Message{}, err
	}
	// Buffer the single response so a response racing context cancellation can
	// never block the DTX reader after the caller has returned.
	responseChannel := make(chan Message, 1)
	d.AddResponseWaiter(identifier, responseChannel)
	defer d.removeResponseWaiter(identifier)
	if err := ctx.Err(); err != nil {
		return Message{}, err
	}
	select {
	case <-d.connection.Closed():
		err := d.connection.Err()
		if err == nil {
			err = ErrConnectionClosed
		}
		return Message{}, err
	default:
	}

	err = d.connection.Send(bytes)
	if err != nil {
		return Message{}, err
	}
	select {
	case response := <-responseChannel:
		return response, nil
	case <-ctx.Done():
		return Message{}, fmt.Errorf("waiting for response for message:%d channel:%d: %w", identifier, d.channelCode, ctx.Err())
	case <-d.connection.Closed():
		err := d.connection.Err()
		if err == nil {
			err = ErrConnectionClosed
		}
		return Message{}, fmt.Errorf("waiting for response for message:%d channel:%d: %w", identifier, d.channelCode, err)
	}
}

func (d *Channel) Dispatch(msg Message) {
	d.mutex.Lock()
	d.cleanupStaleDefragmentersLocked(time.Now())
	if msg.Identifier >= d.messageIdentifier {
		d.messageIdentifier = msg.Identifier + 1
	}
	if msg.PayloadHeader.MessageType == Methodinvocation && len(msg.Payload) > 0 {
		selector, isSelector := msg.Payload[0].(string)
		if isSelector {
			log.Trace("Dispatching:", selector)
		}
		if v, ok := d.registeredMethods[selector]; isSelector && ok {
			d.mutex.Unlock()
			SendAckIfNeeded(d.connection, msg)
			select {
			case v <- msg:
				return
			case <-d.connection.Closed():
				return
			default:
			}
			// Remote accessibility callbacks must never block the sole reader.
			// Preserve a bounded recent queue and discard the oldest callback if
			// the consumer is temporarily slower than the device.
			select {
			case <-v:
			default:
			}
			select {
			case v <- msg:
			case <-d.connection.Closed():
			default:
			}
			return
		}
	}
	d.mutex.Unlock()
	if msg.ConversationIndex > 0 || msg.IsFragment() {
		d.dispatchResponseOrFragment(msg)
		return
	}
	if d.messageDispatcher != nil {
		d.messageDispatcher.Dispatch(msg)
	}
}

func (d *Channel) dispatchResponseOrFragment(msg Message) {
	if msg.IsFirstFragment() {
		d.mutex.Lock()
		if msg.ConversationIndex > 0 {
			if _, waiting := d.responseWaiters[msg.Identifier]; !waiting {
				d.mutex.Unlock()
				SendAckIfNeeded(d.connection, msg)
				log.WithFields(log.Fields{
					"channel_id": d.channelName,
					"message_id": msg.Identifier,
				}).Debug("dropping late fragmented DTX response without a waiter")
				return
			}
		}
		if d.defragmenters == nil {
			d.defragmenters = make(map[int]*FragmentDecoder)
		}
		decoder := NewFragmentDecoder(msg)
		if decoder == nil {
			d.mutex.Unlock()
			SendAckIfNeeded(d.connection, msg)
			log.WithFields(log.Fields{
				"channel_id": d.channelName,
				"message_id": msg.Identifier,
			}).Warn("dropping invalid or oversized DTX fragment assembly")
			return
		}
		if !d.canStoreDefragmenterLocked(msg.Identifier, decoder) {
			d.mutex.Unlock()
			SendAckIfNeeded(d.connection, msg)
			log.WithFields(log.Fields{
				"channel_id": d.channelName,
				"message_id": msg.Identifier,
			}).Warn("dropping DTX fragment assembly because the channel cache is full")
			return
		}
		d.defragmenters[msg.Identifier] = decoder
		d.mutex.Unlock()
		SendAckIfNeeded(d.connection, msg)
		return
	}

	if msg.IsFragment() {
		d.mutex.Lock()
		defragmenter, ok := d.defragmenters[msg.Identifier]
		if !ok {
			d.mutex.Unlock()
			log.Warn("Received message fragment without first message, dropping it")
			return
		}
		if !defragmenter.AddFragment(msg) {
			delete(d.defragmenters, msg.Identifier)
			d.mutex.Unlock()
			log.WithFields(log.Fields{
				"channel_id": d.channelName,
				"message_id": msg.Identifier,
			}).Warn("dropping invalid DTX fragment sequence")
			return
		}
		if !defragmenter.HasFinished() {
			d.mutex.Unlock()
			return
		}
		messageBytes := defragmenter.Extract()
		delete(d.defragmenters, msg.Identifier)
		d.mutex.Unlock()

		decoded, leftover, err := DecodeNonBlocking(messageBytes)
		if err != nil {
			log.WithError(err).Error("decoding fragmented DTX message")
			return
		}
		if len(leftover) != 0 {
			log.Error("decoding fragmented DTX message left trailing bytes")
		}
		if decoded.ConversationIndex > 0 {
			d.deliverResponse(decoded)
		} else if d.messageDispatcher != nil {
			d.messageDispatcher.Dispatch(decoded)
		}
		return
	}

	d.deliverResponse(msg)
}

func (d *Channel) cleanupStaleDefragmentersLocked(now time.Time) {
	for identifier, decoder := range d.defragmenters {
		if decoder.firstFragment.ConversationIndex == 0 && decoder.stale(now, fragmentAssemblyTTL) {
			delete(d.defragmenters, identifier)
		}
	}
}

func (d *Channel) canStoreDefragmenterLocked(identifier int, candidate *FragmentDecoder) bool {
	count := 1
	bytes := fragmentAssemblyCost(candidate)
	for existingIdentifier, decoder := range d.defragmenters {
		if existingIdentifier == identifier {
			continue
		}
		count++
		bytes += fragmentAssemblyCost(decoder)
		if count > maxDTXFragmentAssembliesPerChannel || bytes > maxDTXFragmentCacheBytesPerChannel {
			return false
		}
	}
	return count <= maxDTXFragmentAssembliesPerChannel && bytes <= maxDTXFragmentCacheBytesPerChannel
}

func fragmentAssemblyCost(decoder *FragmentDecoder) int64 {
	return int64(decoder.firstFragment.MessageLength) +
		int64(decoder.firstFragment.Fragments)*fragmentAssemblyMetadataBytesPerPiece
}

func (d *Channel) deliverResponse(msg Message) {
	waiter := d.takeResponseWaiter(msg.Identifier)
	if waiter == nil {
		log.WithFields(log.Fields{
			"channel_id": d.channelName,
			"message_id": msg.Identifier,
		}).Debug("dropping late DTX response without a waiter")
		return
	}
	select {
	case waiter <- msg:
	case <-d.connection.Closed():
	}
}
