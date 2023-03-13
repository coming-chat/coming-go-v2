package redis

import "github.com/go-redis/redis/v8"

type Client struct {
	*redis.Client
}

var RedisClient *Client

func NewClient(address, password string, db int) {
	RedisClient = &Client{
		redis.NewClient(&redis.Options{
			Addr:     address,
			Password: password,
			DB:       db,
		}),
	}

	RedisClient.
}
