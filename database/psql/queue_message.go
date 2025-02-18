package psql

import (
	log "github.com/sirupsen/logrus"
	"gorm.io/datatypes"
	"time"
)

type QueueMessage struct {
	Id              int64          `gorm:"type:bigSerial;primaryKey;autoIncrement" json:"id"`
	Message         datatypes.JSON `gorm:"type:jsonb;" json:"message"`
	GroupId         string         `gorm:"size:100" json:"groupId"`
	Topic           string         `gorm:"size:100;not null" json:"topic"`
	Key             string         `gorm:"size:255;" json:"key"`
	Status          string         `gorm:"size:10;not null" json:"status"`
	ManualProcess   bool           `gorm:"type:bool;not null;default:false" json:"manualProcess"`
	ErrReason       string         `gorm:"type:text;" json:"errReason"`
	CreateTime      time.Time      `gorm:"type:timestamp;not null;default:now()" json:"createTime"`
	UpdateTime      time.Time      `gorm:"type:timestamp;not null;default:now()" json:"updateTime"`
	AutoCustomCount int            `gorm:"type:int;not null;default:1" json:"autoCustomCount"`
}

func (q QueueMessage) TableName() string {
	return tablePrefix + "queue_message"
}

func (d *DBStore) CreateQueueMessages(list []QueueMessage) bool {
	err := d.Model(&QueueMessage{}).Create(list).Error
	if err != nil {
		log.Errorf("save failed queue message err: %v", err)
		return false
	}
	return true
}

func (d *DBStore) GetQueueMessage(size int) []*QueueMessage {
	var result []*QueueMessage
	err := d.Model(&QueueMessage{}).Where(
		"manual_process = ? and status = ?",
		false,
		"failed",
	).Order("id ASC").Limit(size).Find(&result).Error
	if err != nil {
		log.Errorf("query failed queue message failed: %v", err)
	}
	return result
}

func (d *DBStore) UpdateQueueMessage(message *QueueMessage) {
	err := d.Model(&QueueMessage{}).Where(
		"id = ? and status = ? and manual_process = ? and update_time = ?",
		message.Id,
		"failed",
		false,
		message.UpdateTime,
	).Select("status", "manual_process", "err_reason", "auto_custom_count").Updates(&message).Error
	if err != nil {
		log.Errorf("update queue message err: %v", err)
	}
}
