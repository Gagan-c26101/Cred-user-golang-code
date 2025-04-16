package models

import (
	"gorm.io/gorm"
)

type Portfolio struct {
	gorm.Model
	UserID               string  `gorm:"not null;index" json:"user_id"`
	Coin                 string  `gorm:"not null" json:"coin"`
	TotalAmount          float64 `gorm:"default:0" json:"total_amount"`
	AvgBuyPrice          float64 `gorm:"default:0" json:"avg_buy_price"`
	TotalInvested        float64 `gorm:"default:0" json:"total_invested"`
	ProfitLoss           float64 `gorm:"default:0" json:"profit_loss"`
	ProfitLossPercentage float64 `json:"profit_loss_percentage"`
}
