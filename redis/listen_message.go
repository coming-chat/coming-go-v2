package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	textsecure "github.com/coming-chat/coming-go-v2"
	"github.com/coming-chat/coming-go-v2/axolotl"
	"github.com/coming-chat/coming-go-v2/database"
	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ListenTopic string
	GroupId     string
	Wg          *sync.WaitGroup
	msgSendPool chan struct{}
)

const (
	customer = "coming-go-client-1"
	msgCount = 1
)

func ListenMessage(ctx context.Context) {
	consumePendingMessage()
	go TrimQueueList(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			message, err := RedisClient.ReadGroupMessages(ListenTopic, GroupId, customer, msgCount)
			if err != nil {
				log.Errorf("redis fetch message err: %v", err)
				continue
			}
			for _, v := range message {
				msgSendPool <- struct{}{}
				go consumeMessageWithAck(v)
			}
		}

	}
}

func InitCustomer() error {
	var (
		NeedCreateGroup   = true
		NeedCreateConsume = true
	)
	Wg = &sync.WaitGroup{}
	msgSendPool = make(chan struct{}, 5)
	groups, err := RedisClient.GetTopicGroups(ListenTopic)
	if err != nil && strings.Index(err.Error(), "ERR no such key") == -1 {
		return err
	} else if err == nil {
		for _, v := range groups {
			if v.Name != GroupId {
				continue
			}
			NeedCreateGroup = false
			var consumers []redis.XInfoConsumer
			consumers, err = RedisClient.GetConsumer(ListenTopic, GroupId)
			if err != nil && strings.Index(err.Error(), "ERR no such key") == -1 {
				return err
			} else if err == nil {
				for _, v := range consumers {
					if v.Name == customer {
						NeedCreateConsume = false
						return nil
					}
				}
			}
		}
	}

	if NeedCreateGroup {
		err = RedisClient.CreateGroup(ListenTopic, GroupId, "0-0")
		if err != nil {
			return err
		}
	}

	if NeedCreateConsume {
		err = RedisClient.CreateConsumer(ListenTopic, GroupId, customer)
		if err != nil {
			return err
		}
	}

	return nil
}

func getPendingMessageAndConsume(start string) ([]redis.XPendingExt, error) {
	pendingMessages, err := RedisClient.GetCustomerPendingMessage(&redis.XPendingExtArgs{
		Stream:   ListenTopic,
		Group:    GroupId,
		Start:    start,
		End:      "+",
		Count:    msgCount,
		Consumer: customer,
	})
	if err != nil {
		return nil, err
	}
	if len(pendingMessages) == 0 {
		return nil, nil
	}
	var messageIds []string
	for _, v := range pendingMessages {
		messageIds = append(messageIds, v.ID)
	}
	messages, err := RedisClient.ClaimPendingMessage(&redis.XClaimArgs{
		Group:    GroupId,
		Stream:   ListenTopic,
		Consumer: customer,
		MinIdle:  1 * time.Second,
		Messages: messageIds,
	})
	if err != nil {
		return nil, err
	}
	for _, v := range messages {
		if err = consumeMessage(v); err != nil {
			log.Errorf("process message: %v with err: %v", v, err)
			err = consumeErrMsg(v, err)
			if err != nil {
				log.Errorf("save failed message err: %v", err)
				continue
			}
		}
		err = RedisClient.RelyAck(ListenTopic, GroupId, v)
		if err != nil {
			log.Errorf("redis relay message err: %v", err)
		}
	}
	return pendingMessages, nil
}

func consumePendingMessage() {
	pendingMsgExt, err := getPendingMessageAndConsume("-")
	if err != nil {
		log.Errorf("consume pending message failed: %v", err)
	}
	for len(pendingMsgExt) == msgCount {
		pendingMsgExt, err = getPendingMessageAndConsume(pendingMsgExt[msgCount-1].ID)
		if err != nil {
			if err == redis.Nil {
				return
			}
			log.Errorf("cycle consume pending message failed: %v", err)
			continue
		}
	}
}

func consumeMessageWithAck(message redis.XMessage) {
	Wg.Add(1)
	defer func() {
		<-msgSendPool
		Wg.Done()
	}()
	if err := consumeMessage(message); err != nil {
		log.Errorf("process message: %v with err: %v", message, err)
		err = consumeErrMsg(message, err)
		if err != nil {
			log.Errorf("save failed message err: %v", err)
			return
		}
	}
	err := RedisClient.RelyAck(ListenTopic, GroupId, message)
	if err != nil {
		log.Errorf("redis relay message %v ack err: %v", message, err)
	}
}

func TrimQueueList(ctx context.Context) {
	Wg.Add(1)
	defer func() {
		Wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			streamLen, err := RedisClient.StreamLen(ListenTopic)
			if err != nil {
				log.Errorf("get topic %s lens err: %v", ListenTopic, err)
			}
			if streamLen < 1000 {
				time.Sleep(10 * time.Second)
				continue
			}
			info, err := RedisClient.GetPendingInfo(ListenTopic, GroupId)
			if err != nil {
				log.Errorf("get topic %s group %s pending info err: %v", ListenTopic, GroupId, err)
				continue
			}
			if info.Count == 0 {
				time.Sleep(5 * time.Second)
				continue
			}
			err = RedisClient.TrimStream(ListenTopic, info.Lower)
			if err != nil {
				log.Errorf("trim topic %s failed: %v", ListenTopic, err)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func sendMessage(isGroup bool, to, message string) (err error) {

	if isGroup {
		_, err = textsecure.SendGroupMessage(to, message, 0) // 0 is the expire timer
	} else {
		_, err = textsecure.SendMessage(to, message, 0)
	}
	if nerr, ok := err.(axolotl.NotTrustedError); ok {
		err = fmt.Errorf("Peer identity not trusted. Remove the file .storage/identity/remote_%s to approve\n", nerr.ID)
	}
	return
}

func consumeMessage(message redis.XMessage) (err error) {
	defer func() {
		rec := recover()
		if rec != nil {
			err = fmt.Errorf("consumeMsg %v panic: %v", message, rec)
			return
		}
	}()
	msg := message.Values["message"].(string)
	isGroup, err := strconv.ParseBool(message.Values["isGroup"].(string))
	if err != nil {
		return err
	}
	to := message.Values["to"].(string)

	return sendMessage(isGroup, to, msg)
}

func consumeErrMsg(message redis.XMessage, err error) error {
	msg, err1 := json.Marshal(message.Values)
	if err1 != nil {
		return err1
	}
	if !database.DB.CreateQueueMessages([]database.QueueMessage{
		{
			Message:       msg,
			Key:           message.ID,
			Topic:         ListenTopic,
			ManualProcess: true,
			ErrReason:     err.Error(),
			Status:        "failed",
			GroupId:       GroupId,
		},
	}) {
		return errors.New("save failed message err")
	}
	return nil
}
