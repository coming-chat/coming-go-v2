package redis

import (
	"fmt"
	"github.com/go-redis/redis/v8"
	"time"
)

type Client struct {
	*redis.Client
}

var RedisClient *Client

func NewClient(address, password string, db int) error {
	RedisClient = &Client{
		redis.NewClient(&redis.Options{
			Addr:     address,
			Password: password,
			DB:       db,
		}),
	}

	_, err := RedisClient.Ping(RedisClient.Context()).Result()
	if err != nil {
		return err
	}
	return nil
}

func (r *Client) ReadGroupMessages(topic, group, customer string, count int64) ([]redis.XMessage, error) {
	arg := &redis.XReadGroupArgs{
		Group:    group,
		Consumer: customer,
		Streams:  []string{topic, ">"},
		Count:    count,
		Block:    5 * time.Second,
		NoAck:    false,
	}
	for {
		result, err := r.XReadGroup(r.Context(), arg).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return nil, err
		}
		if len(result) != 1 {
			continue
		}
		return result[0].Messages, nil
	}
}

func (r *Client) RelyAck(topic, group string, message redis.XMessage) error {
	result, err := r.XAck(r.Context(), topic, group, message.ID).Result()
	if err != nil {
		return err
	}
	if result == 1 {
		return nil
	} else {
		return fmt.Errorf("rely ack for message id %s get unknown: %d", message.ID, result)
	}
}

func (r *Client) GetCustomerPendingMessage(arg *redis.XPendingExtArgs) ([]redis.XPendingExt, error) {
	result, err := r.XPendingExt(r.Context(), arg).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (r *Client) ClaimPendingMessage(arg *redis.XClaimArgs) ([]redis.XMessage, error) {
	return r.XClaim(r.Context(), arg).Result()
}

func (r *Client) PushMessageToStream(arg *redis.XAddArgs) error {
	_, err := r.XAdd(r.Context(), arg).Result()
	if err != nil {
		return err
	}
	return nil
}

func (r *Client) CreateGroup(topic, groupId, start string) error {
	_, err := r.XGroupCreateMkStream(r.Context(), topic, groupId, start).Result()
	return err
}

func (r *Client) GetTopicGroups(topic string) ([]redis.XInfoGroup, error) {
	return r.XInfoGroups(r.Context(), topic).Result()
}

func (r *Client) GetConsumer(topic, group string) ([]redis.XInfoConsumer, error) {
	return r.XInfoConsumers(r.Context(), topic, group).Result()
}

func (r *Client) CreateConsumer(topic, group, consumer string) error {
	_, err := r.XGroupCreateConsumer(r.Context(), topic, group, consumer).Result()
	return err
}

func (r *Client) GetPendingInfo(topic, group string) (*redis.XPending, error) {
	return r.XPending(r.Context(), topic, group).Result()
}

func (r *Client) TrimStream(topic, miniID string) error {
	_, err := r.XTrimMinIDApprox(r.Context(), topic, miniID, 0).Result()
	return err
}

func (r *Client) StreamLen(topic string) (int64, error) {
	return r.XLen(r.Context(), topic).Result()
}
