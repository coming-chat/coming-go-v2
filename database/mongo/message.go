package mongo

import (
	"github.com/coming-chat/coming-go-v2/groupsv2"
	protobuf "github.com/coming-chat/coming-go-v2/protobuf"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

const collectionName = "coming_message"

type Message struct {
	Message    string    `json:"message"`
	Cid        string    `json:"cid"`
	Uuid       string    `json:"uuid"`
	Timestamp  time.Time `json:"timestamp"`
	Direction  string    `json:"from"`
	GroupHexId string    `json:"group"`
	GroupName  string    `json:"groupName"`
	Delete     bool      `json:"delete"`
	Quote      any       `json:"quote"`
}

func (d *DBStore) SavaReceiveMessage(source, sourceUUID, message string, timestamp int64, groupV2 *groupsv2.GroupV2, quoteData *protobuf.DataMessage_Quote) error {
	var (
		groupId, groupName string
	)

	if groupV2 != nil {
		groupId = groupV2.Hexid
		groupName = groupV2.DecryptedGroup.Title
	}

	_, err := d.Database(d.databaseName).Collection(collectionName).InsertOne(d.ctx, bson.M{
		"msg_id":       timestamp,
		"message":      message,
		"cid":          source,
		"uuid":         sourceUUID,
		"timestamp":    time.UnixMilli(timestamp),
		"direction":    "From",
		"group_hex_id": groupId,
		"group_name":   groupName,
		"delete":       false,
		"quote":        quoteData,
	})
	return err
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
	_, err := d.Database(d.databaseName).Collection(collectionName).InsertOne(d.ctx, bson.M{
		"msg_id":       msg.GetTimestamp(),
		"message":      msg.GetBody(),
		"cid":          cid,
		"uuid":         "",
		"timestamp":    time.UnixMilli(int64(msg.GetTimestamp())),
		"direction":    "To",
		"group_hex_id": groupHexId,
		"groupName":    "",
		"delete":       false,
	})
	return err
}
