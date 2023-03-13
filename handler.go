package textsecure

import (
	"github.com/coming-chat/coming-go-v2/attachments"
	"github.com/coming-chat/coming-go-v2/groupsv2"
	signalservice "github.com/coming-chat/coming-go-v2/protobuf"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

var UseGroup bool

func handleMessage(srcE164 string, srcUUID string, timestamp uint64, b []byte) error {

	content := &signalservice.Content{}
	err := proto.Unmarshal(b, content)
	if err != nil {
		log.Errorln("[textsecure] handleMessage umarshalling", err)
		return err
	}
	log.Debugln("[textsecure] handleMessage")

	if dm := content.GetDataMessage(); dm != nil {
		return handleDataMessage(srcE164, srcUUID, timestamp, dm)
	} else if sm := content.GetSyncMessage(); sm != nil {
		return handleSyncMessage(srcE164, srcUUID, timestamp, sm)
	} else if cm := content.GetCallMessage(); cm != nil {
		return handleCallMessage(srcE164, srcUUID, timestamp, cm)
	} else if rm := content.GetReceiptMessage(); rm != nil {
		return handleReceiptMessage(srcE164, srcUUID, timestamp, rm)
	} else if tm := content.GetTypingMessage(); tm != nil {
		return handleTypingMessage(srcE164, srcUUID, timestamp, tm)
	} else if nm := content.GetNullMessage(); nm != nil {
		log.Errorln("[textsecure] Nullmessage content received", content)
		return nil
	}
	//FIXME get the right content
	// log.Errorf(content)
	log.Errorln("[textsecure] Unknown message content received", content)
	return nil
}

func handleTypingMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.TypingMessage) error {

	msg := &Message{
		Source:     src,
		SourceUUID: srcUUID,
		Message:    "typingMessage",
		Timestamp:  timestamp,
	}

	if client.TypingMessageHandler != nil {
		client.TypingMessageHandler(msg)
	}
	return nil
}
func handleReceiptMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.ReceiptMessage) error {
	msg := &Message{
		Source:     src,
		SourceUUID: srcUUID,
		Message:    "sentReceiptMessage",
		Timestamp:  cm.GetTimestamp()[0],
	}
	if *cm.Type == signalservice.ReceiptMessage_READ {
		msg.Message = "readReceiptMessage"
	}
	if *cm.Type == signalservice.ReceiptMessage_DELIVERY {
		msg.Message = "deliveryReceiptMessage"
	}
	if client.ReceiptMessageHandler != nil {
		client.ReceiptMessageHandler(msg)
	}

	return nil
}

// handleDataMessage handles an incoming DataMessage and calls client callbacks
func handleDataMessage(src string, srcUUID string, timestamp uint64, dm *signalservice.DataMessage) error {
	flags, err := handleFlags(srcUUID, dm)
	if err != nil {
		return err
	}

	atts, err := attachments.HandleAttachments(dm)
	if err != nil {
		return err
	}
	log.Debugln("[textsecure] handleDataMessage", timestamp, *dm.Timestamp, dm.GetExpireTimer())
	if !UseGroup && dm.GetGroupV2() != nil {
		return nil
	}

	gr2, err := groupsv2.HandleGroupsV2(src, dm)
	if err != nil {
		return err
	}

	msg := &Message{
		Source:                  src,
		SourceUUID:              srcUUID,
		Message:                 dm.GetBody(),
		Attachments:             atts,
		GroupV2:                 gr2,
		Flags:                   flags,
		ExpireTimer:             dm.GetExpireTimer(),
		ProfileKey:              dm.GetProfileKey(),
		Timestamp:               dm.GetTimestamp(),
		Quote:                   dm.GetQuote(),
		Contact:                 dm.GetContact(),
		Sticker:                 dm.GetSticker(),
		Reaction:                dm.GetReaction(),
		RequiredProtocolVersion: dm.GetRequiredProtocolVersion(),
		IsViewOnce:              dm.GetIsViewOnce(),
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}
func handleCallMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.CallMessage) error {
	message := "Call "
	if m := cm.GetAnswer(); m != nil {
		message += "answer"
	}
	if m := cm.GetOffer(); m != nil {
		message += "offer"
	}
	if m := cm.GetHangup(); m != nil {
		message += "hangup"
	}
	if m := cm.GetBusy(); m != nil {
		message += "busy"
	}
	if m := cm.GetLegacyHangup(); m != nil {
		message += "hangup"
	}
	if m := cm.GetMultiRing(); m == true {
		message += "ring "
	}
	if m := cm.GetIceUpdate(); m != nil {
		message += "ring"
	}
	if m := cm.GetOpaque(); m != nil {
		message += "opaque"
	}

	msg := &Message{
		Source:     src,
		SourceUUID: srcUUID,
		Message:    message,
		Timestamp:  timestamp,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}

func handleUnidentifiedSenderMessage(srcUUID string, timestamp uint64, sm *signalservice.SyncMessage) error {
	return nil
}
