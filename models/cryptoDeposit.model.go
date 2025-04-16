package models

import (
	"time"

	"gorm.io/gorm"
)

// Status form fiatDepositModel
// CryptoDeposit Model
type CryptoDeposit struct {
	gorm.Model
	UserID        string     `gorm:"not null" json:"user_id"`
	Amount        float64    `gorm:"default:0" json:"crypto_amount"`
	Currency      string     `gorm:"not null" json:"currency"` // e.g., BTC, ETH, USDT
	Symbol        string     `gorm:"not null" json:"symbol"`
	Status        Status     `gorm:"type:varchar(20);default:'pending';check:status IN ('pending', 'confirmed', 'failed', 'processing')" json:"status"`
	WalletAddress string     `gorm:"not null" json:"wallet_address"`
	TxHash        string     `gorm:"not null;unique" json:"tx_hash"`
	Decimal       float64    `gorm:"default:18"`
	Network       string     `gorm:"not null" json:"network"` // e.g., Ethereum, BSC, Solana
	BlockNo       float64    `gorm:"not null" json:"block_number"`
	ConfirmedAt   *time.Time `json:"confirmed_at"`
	Description   string     `json:"description"`
	IsDeleted     bool       `gorm:"default:false"`
}
