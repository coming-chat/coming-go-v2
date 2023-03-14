package redis

import (
	"encoding/json"
	"github.com/coming-chat/coming-go-v2/groupsv2"
	signalservice "github.com/coming-chat/coming-go-v2/protobuf"
	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
)

func SendMessageToRedis(redisMsgRecTopic, msg, source, uuid string, timestamp uint64, groupV2 *groupsv2.GroupV2, quote *signalservice.DataMessage_Quote) {
	groupName := ""
	from := source
	if groupV2 != nil {
		groupName = groupV2.DecryptedGroup.Title
		from = groupV2.Hexid
	}
	quoteMsg := make(map[string]interface{})
	if quote != nil {
		quoteMsg["id"] = quote.GetId()
		quoteMsg["cid"] = quote.GetAuthorE164()
		quoteMsg["uuid"] = quote.GetAuthorUuid()
		quoteMsg["text"] = quote.GetText()
	}
	quoteB, err := json.Marshal(quoteMsg)
	if err != nil {
		log.Errorf("push message to redis failed: %v", err)
	}

	err = RedisClient.PushMessageToStream(&redis.XAddArgs{
		Stream:     redisMsgRecTopic,
		NoMkStream: false,
		Values: map[string]interface{}{
			"from":      from,
			"message":   msg,
			"cid":       source,
			"uuid":      uuid,
			"timestamp": timestamp,
			"group":     groupName,
			"quote":     string(quoteB),
		},
	})
	if err != nil {
		log.Errorf("push message to redis failed: %v", err)
	}
}
