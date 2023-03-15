package textsecure

import (
	"github.com/coming-chat/coming-go-v2/database"
	"time"

	"github.com/coming-chat/coming-go-v2/config"
	signalservice "github.com/coming-chat/coming-go-v2/protobuf"
	"github.com/coming-chat/coming-go-v2/unidentifiedAccess"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

func sendMessage(msg *outgoingMessage) (uint64, error) {
	// todo use UnidentifiedSenderMessage

	if _, ok := deviceLists[msg.destination]; !ok {
		deviceLists[msg.destination] = []uint32{1}
	}

	dm := createMessage(msg)

	content := &signalservice.Content{
		DataMessage: dm,
	}
	if database.PostgresMode && msg.msg != "" {
		isGroup := false
		if msg.groupV2 != nil {
			isGroup = true
		}
		err := database.DB.SaveSendDataMessage(dm, msg.destination, isGroup)
		if err != nil {
			log.Errorf("save send message error: %v", err)
		}
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(msg.destination, padMessage(b), false, dm.Timestamp)
	if err != nil {
		return 0, err
	}
	var e164 *string
	var uuid *string

	if msg.destination[0] == '+' {
		e164 = &msg.destination
	} else {
		uuid = &msg.destination
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Needs sync. destination: %s", msg.destination)
		sm := &signalservice.SyncMessage{
			Sent: &signalservice.SyncMessage_Sent{
				DestinationE164: e164,
				DestinationUuid: uuid,
				Timestamp:       dm.Timestamp,
				Message:         dm,
			},
		}

		_, serr := sendSyncMessage(sm, dm.Timestamp)
		if serr != nil {
			log.WithFields(log.Fields{
				"error":       serr,
				"destination": msg.destination,
				"timestamp":   resp.Timestamp,
			}).Error("Failed to send sync message")
		}
	}
	return resp.Timestamp, err
}

// TODO switch to uuids
func sendSyncMessage(sm *signalservice.SyncMessage, timestamp *uint64) (uint64, error) {
	log.Debugln("[textsecure] sendSyncMessage", timestamp)
	user := config.ConfigFile.Tel //TODO: switch tu uuid
	if config.ConfigFile.UUID != "" {
		user = config.ConfigFile.UUID
	}
	if _, ok := deviceLists[user]; !ok {
		deviceLists[user] = []uint32{1}
	}

	content := &signalservice.Content{
		SyncMessage: sm,
	}

	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(user, padMessage(b), true, timestamp)
	return resp.Timestamp, err
}

func sendVerifiedMessage(verified *signalservice.Verified, unidentifiedAccess *unidentifiedAccess.UnidentifiedAccess) error {
	omsg := &outgoingNullMessage{
		destination: verified.GetDestinationUuid(),
		msg: &signalservice.NullMessage{
			Padding: []byte{},
		},
	}
	_, err := sendNullMessage(omsg)
	return err
}

type outgoingNullMessage struct {
	destination string
	msg         *signalservice.NullMessage
}

func sendNullMessage(msg *outgoingNullMessage) (uint64, error) {
	if _, ok := deviceLists[msg.destination]; !ok {
		deviceLists[msg.destination] = []uint32{1}
	}

	content := &signalservice.Content{
		NullMessage: msg.msg,
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	now := uint64(time.Now().UnixNano() / 1000000)

	resp, err := buildAndSendMessage(msg.destination, padMessage(b), false, &now)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Nullmessage needs sync. destination: %s", msg.destination)
	}
	return resp.Timestamp, err
}

type outgoingReceiptMessage struct {
	Destination string
	DELIVERY    []uint64
	READ        []uint64
}

func sendReceiptMessage(msg *outgoingReceiptMessage) (uint64, error) {
	if _, ok := deviceLists[msg.Destination]; !ok {
		deviceLists[msg.Destination] = []uint32{1}
	}
	var content *signalservice.Content
	switch {
	case len(msg.DELIVERY) != 0:
		deliveryType := signalservice.ReceiptMessage_DELIVERY
		content = &signalservice.Content{
			ReceiptMessage: &signalservice.ReceiptMessage{
				Type:      &deliveryType,
				Timestamp: msg.DELIVERY,
			},
		}
	case len(msg.READ) != 0:
		readType := signalservice.ReceiptMessage_READ
		content = &signalservice.Content{
			ReceiptMessage: &signalservice.ReceiptMessage{
				Type:      &readType,
				Timestamp: msg.READ,
			},
		}
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	now := uint64(time.Now().UnixNano() / 1000000)

	resp, err := buildAndSendMessage(msg.Destination, padMessage(b), false, &now)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Receiptmessage needs sync. destination: %s", msg.Destination)
	}
	return resp.Timestamp, err
}

func sendTypingMessage(destination string, msgId uint64, action signalservice.TypingMessage_Action) (uint64, error) {
	if _, ok := deviceLists[destination]; !ok {
		deviceLists[destination] = []uint32{1}
	}
	content := &signalservice.Content{
		TypingMessage: &signalservice.TypingMessage{
			Action:    &action,
			Timestamp: &msgId,
		},
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	now := uint64(time.Now().UnixNano() / 1000000)

	resp, err := buildAndSendMessage(destination, padMessage(b), false, &now)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] TypingStartmessage needs sync. destination: %s", destination)
	}
	return resp.Timestamp, err
}
