package psql

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	DB *DBStore
)

const tablePrefix = "coming_"

type DBStore struct {
	*gorm.DB
}

func NewDB(dsn string) error {
	db, err := gorm.Open(postgres.Open(dsn))
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
