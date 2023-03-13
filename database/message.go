package database

import (
	"encoding/json"
	textsecure "github.com/coming-chat/coming-go-v2"
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
	GroupHexId string         `gorm:"type:varchar(100)" json:"group"`
	GroupName  string         `gorm:"type:varchar(255)" json:"groupName"`
	Delete     bool           `gorm:"type:bool;default:false" json:"delete"`
	Quote      datatypes.JSON `gorm:"type:jsonb" json:"quote"`
}

func (d *DBStore) SavaMessage(msg *textsecure.Message) error {
	var (
		groupId, groupName string
		err                error
		quote              []byte
	)

	if msg.GroupV2 != nil {
		groupId = msg.GroupV2.Hexid
		groupName = msg.GroupV2.DecryptedGroup.Title
	}
	if msg.Quote != nil {
		quote, err = json.Marshal(msg.Quote)
		if err != nil {
			return err
		}
	}
	return d.Model(&Message{}).Create(&Message{
		MsgId:      int64(msg.Timestamp),
		Message:    msg.Message,
		Cid:        msg.Source,
		Uuid:       msg.SourceUUID,
		Timestamp:  time.UnixMilli(int64(msg.Timestamp)),
		Direction:  "From",
		GroupHexId: groupId,
		GroupName:  groupName,
		Quote:      quote,
	}).Error
}
