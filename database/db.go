package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const tablePrefix = "coming_"

type DBStore struct {
	*gorm.DB
}

var DB *DBStore

func NewDB(url, username, password, dbName string) error {
	db, err := gorm.Open(postgres.Open("host=" + url + " port=5432" + " user=" + username + " password='" + password +
		"' dbname=" + dbName + " sslmode=disable"))
	if err != nil {
		return err
	}

	DB = &DBStore{
		db,
	}
	err = DB.Migrate()
	if err != nil {
		return err
	}
	return nil
}

func (d *DBStore) Migrate() error {
	err := d.AutoMigrate(&Message{}, &QueueMessage{})
	if err != nil {
		return err
	}
	return nil
}
