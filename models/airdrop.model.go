package models

import (
	"time"

	"gorm.io/gorm"
)

// AirdropType Enum
type AirdropType string

const (
	OnReferral           AirdropType = "on_referral"
	OnKYC                AirdropType = "on_kyc"
	OnFirstCryptoDeposit AirdropType = "on_first_crypto_deposit"
	OnFirstFiatDeposit   AirdropType = "on_first_fiat_deposit"
)

// Status Enum
type AirdropStatus string

const (
	Active   AirdropStatus = "active"
	Deactive AirdropStatus = "deactive"
)

// Airdrop Model
type Airdrop struct {
	gorm.Model
	AdminID      string        `gorm:"not null" json:"admin_id"`
	Type         AirdropType   `gorm:"type:varchar(30);default:'on_referral';check:type IN ('on_referral', 'on_kyc', 'on_first_crypto_deposit', 'on_first_fiat_deposit')" json:"type"`
	CurrencyID   uint          `gorm:"not null;index" json:"currency_id"` // Foreign key reference to Currency model
	StartDate    time.Time     `gorm:"not null" json:"start_date"`
	EndDate      time.Time     `gorm:"not null" json:"end_date"`
	Amount       float64       `gorm:"not null;default:0" json:"amount"` // Amount in USD
	FiatCurrency string        `gorm:"not null" json:"fiat_currency"`
	Status       AirdropStatus `gorm:"type:varchar(10);default:'active';check:status IN ('active', 'deactive')" json:"status"`
	IsDeleted    bool          `gorm:"default:false"`
}
