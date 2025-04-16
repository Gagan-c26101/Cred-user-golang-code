package models

import (
	"time"

	"gorm.io/gorm"
)

type UserFiatWallet struct {
	gorm.Model
	UserID    string  `gorm:"index;not null" json:"user_id"`
	Currency  string  `gorm:"type:varchar(3);not null;index" json:"currency"` // e.g., INR, USD
	Balance   float64 `gorm:"default:0" json:"balance"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
