package models

import (
	"gorm.io/gorm"
)

type AmlUserData struct {
	gorm.Model
	UserID         string `gorm:"not null" json:"user_id"`
	Occupation     string `json:"occupation"`
	SourceOfIncome string `json:"source_of_income"`
	ScaleOfIncome  string `json:"scale_of_income"`
	TradingExp     string `json:"trading_exp"`
	TaxLiability   string `json:"tax_liability"`
	TermsCondition string `json:"terms_condition"`
}
