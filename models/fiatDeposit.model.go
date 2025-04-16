package models

import (
	"time"

	"gorm.io/gorm"
)

// Status Enum
type Status string

const (
	Pending    Status = "pending"
	Approved   Status = "approved"
	Rejected   Status = "rejected"
	Processing Status = "processing"
)

// BankPaymentType Enum
type BankPaymentType string

const (
	NEFT BankPaymentType = "NEFT"
	IMPS BankPaymentType = "IMPS"
	UPI  BankPaymentType = "UPI"
)

type FiatDeposit struct {
	gorm.Model
	UserID          string          `gorm:"not null;index" json:"user_id"`
	Amount          float64         `gorm:"default:0" json:"fiat_amount"`
	Currency        string          `gorm:"type:varchar(3);not null" json:"currency"` // ISO 4217 currency code (e.g., USD, INR)
	TransactionID   string          `gorm:"index" json:"transaction_id"`
	Status          Status          `gorm:"type:varchar(20);default:'pending';index;check:status IN ('pending', 'approved', 'rejected', 'processing')" json:"status"`
	BankPaymentType BankPaymentType `gorm:"type:varchar(10);check:bank_payment_type IN ('NEFT', 'IMPS', 'UPI')" json:"bank_payment_type"`
	Image           string          `gorm:"default:''" json:"image"`
	ApprovedBy      string          `json:"approved_by"`
	Description     string          `json:"description"`
	AdminActionDate *time.Time      `json:"admin_action_date"`
	IsDeleted       bool            `gorm:"default:false"`
}

type FiatWithdraw struct {
	gorm.Model
	UserID          string     `gorm:"not null;index" json:"user_id"`
	Amount          float64    `gorm:"default:0" json:"amount"`
	Currency        string     `gorm:"type:varchar(3);not null" json:"currency"`
	Status          Status     `gorm:"type:varchar(20);default:'pending';index;check:status IN ('pending', 'approved', 'rejected', 'processing')" json:"status"`
	BankAccount     string     `gorm:"type:text" json:"bank_account"` // Optional: could be JSON or raw bank details
	Remarks         string     `gorm:"type:text" json:"remarks"`      // Optional: user note or description
	ApprovedBy      string     `json:"approved_by"`
	RejectedBy      string     `json:"rejected_by"`                     // Admin who approved
	AdminActionDate *time.Time `json:"admin_action_date"`               // When admin approved/rejected
	IsDeleted       bool       `gorm:"default:false" json:"is_deleted"` // Soft delete
}
