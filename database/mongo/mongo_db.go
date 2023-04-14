package mongo

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	"time"
)

var (
	DB *DBStore
)

type DBStore struct {
	*mongo.Client
	databaseName string
	ctx          context.Context
}

func New(mongoUrl string, ctx context.Context) (err error) {
	mdb, databaseName, err := NewMongoEngine(mongoUrl)
	if err != nil {
		return fmt.Errorf("init mongodb err: %v", err.Error())
	}

	DB = &DBStore{
		Client:       mdb,
		databaseName: databaseName,
		ctx:          ctx,
	}
	return
}

func (d *DBStore) Disconnect() {
	d.Client.Disconnect(d.ctx)
}

func NewMongoEngine(url string) (*mongo.Client, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(url).SetMinPoolSize(10).SetMaxConnIdleTime(10*time.Second))
	if err != nil {
		return nil, "", err
	}
	err = client.Ping(ctx, readpref.Primary())

	urlInfo, _ := connstring.ParseAndValidate(url)

	if err != nil {
		return nil, "", fmt.Errorf("mongo ping fail: %v", err)
	}
	return client, urlInfo.Database, nil
}
