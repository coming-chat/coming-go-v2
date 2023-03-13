package textsecure

import (
	"github.com/coming-chat/coming-go-v2/attachments"
	"github.com/coming-chat/coming-go-v2/groupsv2"
	signalservice "github.com/coming-chat/coming-go-v2/protobuf"
)

// Message represents a message received from the peer.
// It can optionally include attachments and be sent to a group.
type Message struct {
	SourceUUID              string
	Source                  string
	Message                 string
	Attachments             []*attachments.Attachment
	Group                   *Group
	GroupV2                 *groupsv2.GroupV2
	Flags                   uint32
	ExpireTimer             uint32
	ProfileKey              []byte
	Timestamp               uint64
	Quote                   *signalservice.DataMessage_Quote
	Contact                 []*signalservice.DataMessage_Contact
	Sticker                 *signalservice.DataMessage_Sticker
	RequiredProtocolVersion uint32
	IsViewOnce              bool
	Reaction                *signalservice.DataMessage_Reaction
}
