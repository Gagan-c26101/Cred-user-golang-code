package models

import (
	"time"

	"gorm.io/gorm"
)

// Passbook represents a user's transaction history
type Passbook struct {
	gorm.Model
	UserID                 string    `gorm:"not null" json:"user_id"`
	AdminID                string    `json:"admin_id"`
	UserCodeID             string    `json:"user_code_id"`
	Coin                   string    `json:"coin"`
	Currency               string    `gorm:"not null" json:"currency"`
	TableID                string    `json:"table_id"` // Refers to Transaction or Spot Table ID
	BeforeBalance          float64   `gorm:"default:0" json:"before_balance"`
	AfterBalance           float64   `gorm:"default:0" json:"after_balance"`
	Amount                 float64   `gorm:"default:0" json:"amount"`
	Type                   string    `gorm:"type:varchar(50)" json:"type"` // e.g., fiat_deposit, fiat_withdraw, coin_transfer
	Category               string    `gorm:"type:varchar(10);check:category IN ('credit', 'debit')" json:"category"`
	CreatedAt              time.Time `gorm:"autoCreateTime" json:"created_at"`
	Reason                 string    `json:"reason"`
	Duration               string    `json:"duration"`
	Rate                   float64   `gorm:"default:0" json:"rate"`
	EstimatedEarning       float64   `gorm:"default:0" json:"estimated_earning"`
	FromUserID             string    `json:"from_user_id"`
	ChildUserHoldingAmount float64   `gorm:"default:0" json:"child_user_holding_amount"`
	ChildUserName          string    `json:"child_user_name"`
}
