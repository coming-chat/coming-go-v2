package psql

import (
	"encoding/json"
	"github.com/coming-chat/coming-go-v2/groupsv2"
	protobuf "github.com/coming-chat/coming-go-v2/protobuf"
	"gorm.io/datatypes"
	"time"
)

type Message struct {
	MsgId      int64          `gorm:"type:bigint;not null;default:0;primaryKey" json:"msgId"`
	Message    string         `gorm:"type:text" json:"message"`
	Cid        string         `gorm:"type:varchar(20);primaryKey" json:"cid"`
	Uuid       string         `gorm:"type:varchar(60);primaryKey" json:"uuid"`
	Timestamp  time.Time      `gorm:"type:timestamp;" json:"timestamp"`
	Direction  string         `gorm:"type:varchar(20)" json:"from"`
	GroupHexId string         `gorm:"type:varchar(100);primaryKey" json:"group"`
	GroupName  string         `gorm:"type:varchar(255)" json:"groupName"`
	Delete     bool           `gorm:"type:bool;default:false" json:"delete"`
	Quote      datatypes.JSON `gorm:"type:jsonb" json:"quote"`
}

func (d *DBStore) SavaReceiveMessage(source, sourceUUID, message string, timestamp int64, groupV2 *groupsv2.GroupV2, quoteData *protobuf.DataMessage_Quote) error {
	var (
		groupId, groupName string
		err                error
		quote              []byte
	)

	if groupV2 != nil {
		groupId = groupV2.Hexid
		groupName = groupV2.DecryptedGroup.Title
	}
	if quoteData != nil {
		quote, err = json.Marshal(quoteData)
		if err != nil {
			return err
		}
	}
	return d.Model(&Message{}).Create(&Message{
		MsgId:      timestamp,
		Message:    message,
		Cid:        source,
		Uuid:       sourceUUID,
		Timestamp:  time.UnixMilli(timestamp),
		Direction:  "From",
		GroupHexId: groupId,
		GroupName:  groupName,
		Quote:      quote,
	}).Error
}

func (d *DBStore) SaveSendDataMessage(msg *protobuf.DataMessage, to string, isGroup bool) error {
	var (
		groupHexId = ""
		cid        = ""
	)
	if isGroup {
		groupHexId = to
	} else {
		cid = to
	}
	return d.Model(&Message{}).Create(&Message{
		MsgId:      int64(msg.GetTimestamp()),
		Message:    msg.GetBody(),
		Cid:        cid,
		Uuid:       "",
		Timestamp:  time.UnixMilli(int64(msg.GetTimestamp())),
		Direction:  "To",
		GroupHexId: groupHexId,
		GroupName:  "",
	}).Error
}
