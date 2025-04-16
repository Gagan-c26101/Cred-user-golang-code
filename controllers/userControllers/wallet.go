package userController

import (
	"fib/database"
	"fib/middleware"
	"fib/models"
	"time"

	"github.com/gofiber/fiber/v2"
)

func GetFiatWalletBalance(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	balance, err := GetUserFiatBalance(userID)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to calculate balance", nil)
	}

	err = database.Database.Db.Model(&models.UserFiatWallet{}).
		Where("user_id = ?", userID).
		Update("balance", balance).Error
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update wallet balance", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Balance fetched", fiber.Map{
		"balance": balance,
	})
}

// Helper function to calculate balance from approved deposits and withdrawals
func GetUserFiatBalance(userID string) (float64, error) {
	var depositSum, withdrawalSum float64
	db := database.Database.Db

	// Get total approved deposits
	if err := db.Model(&models.FiatDeposit{}).
		Where("user_id = ? AND status = ?", userID, "approved").
		Select("COALESCE(SUM(amount), 0)").Scan(&depositSum).Error; err != nil {
		return 0, err
	}

	// Get total approved withdrawals
	if err := db.Model(&models.FiatWithdraw{}).
		Where("user_id = ? AND status = ?", userID, "approved").
		Select("COALESCE(SUM(amount), 0)").Scan(&withdrawalSum).Error; err != nil {
		return 0, err
	}

	// Return net balance
	return depositSum - withdrawalSum, nil
}

func RequestFiatDeposit(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string) // Assuming user_id is stored as string in JWT

	var user models.User
	if err := database.Database.Db.Where("id = ?", userID).First(&user).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusNotFound, false, "User not found", nil)
	}

	if !user.IsEmailVerified {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Email not verified", nil)
	}

	if !user.IsMobileVerified {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Mobile number not verified", nil)
	}

	if user.UserKYC == 0 {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "KYC not completed", nil)
	}
	var userKYC models.UserKYC
	if err := database.Database.Db.Where("id = ?", user.UserKYC).First(&userKYC).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "KYC record not found", nil)
	}

	if !userKYC.IsVerified {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "KYC not verified yet", nil)
	}

	var bank models.BankDetails
	if err := database.Database.Db.Where("user_id = ? AND is_verified = ?", userID, true).First(&bank).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Banking details not verified", nil)
	}

	// Parse input
	var body struct {
		Amount          float64                `json:"amount"`
		Currency        string                 `json:"currency"`
		TransactionID   string                 `json:"transaction_id"`
		BankPaymentType models.BankPaymentType `json:"bank_payment_type"`
		Image           string                 `json:"image"` // base64 or URL if you support uploads
		Description     string                 `json:"description"`
	}

	if err := c.BodyParser(&body); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body", nil)
	}
	if body.Amount <= 0 {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Amount must be greater than 0", nil)
	}

	var existing models.FiatDeposit
	if err := database.Database.Db.Where("transaction_id = ? AND user_id = ?", body.TransactionID, userID).First(&existing).Error; err == nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Duplicate transaction ID", nil)
	}

	// Create deposit record
	deposit := models.FiatDeposit{
		UserID:          userID,
		Amount:          body.Amount,
		Currency:        body.Currency,
		TransactionID:   body.TransactionID,
		BankPaymentType: body.BankPaymentType,
		Image:           body.Image,
		Description:     body.Description,
		Status:          models.Pending,
	}

	if err := database.Database.Db.Create(&deposit).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to submit deposit request", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Deposit request submitted successfully", deposit)
}

func ApproveFiatDeposit(c *fiber.Ctx) error {
	depositID := c.Params("id")
	adminID := c.Locals("user_id").(string)

	if c.Locals("role") != "admin" {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Access denied", nil)
	}

	var deposit models.FiatDeposit
	db := database.Database.Db

	if err := db.Where("id = ? AND status = ?", depositID, models.Pending).First(&deposit).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusNotFound, false, "Pending deposit not found", nil)
	}

	// Update deposit status
	now := time.Now()
	deposit.Status = models.Approved
	deposit.AdminActionDate = &now
	deposit.ApprovedBy = adminID

	if err := db.Save(&deposit).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to approve deposit", nil)
	}

	var wallet models.UserFiatWallet
	err := db.Where("user_id = ? AND currency = ?", deposit.UserID, deposit.Currency).First(&wallet).Error

	if err != nil {
		// Create new wallet if not found
		wallet = models.UserFiatWallet{
			UserID:   deposit.UserID,
			Currency: deposit.Currency,
			Balance:  deposit.Amount,
		}
		if err := db.Create(&wallet).Error; err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to create wallet", nil)
		}
	} else {
		// Update existing wallet balance
		wallet.Balance += deposit.Amount
		wallet.UpdatedAt = time.Now()
		if err := db.Save(&wallet).Error; err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update wallet", nil)
		}
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Deposit approved and wallet updated", deposit)
}

func UserFiatDepositHistory(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var deposits []models.FiatDeposit
	if err := database.Database.Db.Where("user_id = ?", userID).Order("created_at desc").Find(&deposits).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to fetch deposit history", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Deposit history fetched", deposits)
}

func RequestFiatWithdrawal(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var body struct {
		Amount      float64 `json:"amount"`
		Currency    string  `json:"currency"`
		Remarks     string  `json:"remarks"`
		BankDetails string  `json:"bank_details"` // or use Bank ID if already verified
	}

	if err := c.BodyParser(&body); err != nil || body.Amount <= 0 {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid data", nil)
	}

	var bank models.BankDetails
	if err := database.Database.Db.Where("id = ? AND user_id = ?", body.BankDetails, userID).First(&bank).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid bank details", nil)
	}

	balance, err := GetUserFiatBalance(userID)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to fetch balance", nil)
	}

	if body.Amount > balance {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Insufficient balance", nil)
	}
	// You can preload bank details if needed:

	withdraw := models.FiatWithdraw{
		UserID:   userID,
		Amount:   body.Amount,
		Currency: body.Currency,
		Remarks:  body.Remarks,
		Status:   models.Pending,
	}

	if err := database.Database.Db.Create(&withdraw).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to submit withdrawal", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Withdrawal request submitted", withdraw)
}

func ApproveFiatWithdrawal(c *fiber.Ctx) error {
	withdrawalID := c.Params("id")
	adminID := c.Locals("user_id").(string)

	if c.Locals("role") != "admin" {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Access denied", nil)
	}

	var withdrawal models.FiatWithdraw
	if err := database.Database.Db.Where("id = ? AND status = ?", withdrawalID, models.Pending).First(&withdrawal).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusNotFound, false, "Pending withdrawal not found", nil)
	}

	withdrawal.Status = models.Approved
	now := time.Now()
	withdrawal.AdminActionDate = &now
	withdrawal.ApprovedBy = adminID

	if err := database.Database.Db.Save(&withdrawal).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to approve withdrawal", nil)
	}

	balance, _ := GetUserFiatBalance(withdrawal.UserID)

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Withdrawal approved", fiber.Map{
		"withdrawal":  withdrawal,
		"new_balance": balance,
	})
}

func RejectFiatWithdrawal(c *fiber.Ctx) error {
	withdrawalID := c.Params("id")
	adminID := c.Locals("user_id").(string)

	if c.Locals("role") != "admin" {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Access denied", nil)
	}

	var withdrawal models.FiatWithdraw
	if err := database.Database.Db.Where("id = ? AND status = ?", withdrawalID, models.Pending).First(&withdrawal).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusNotFound, false, "Pending withdrawal not found", nil)
	}

	withdrawal.Status = models.Rejected
	now := time.Now()
	withdrawal.AdminActionDate = &now
	withdrawal.RejectedBy = adminID

	if err := database.Database.Db.Save(&withdrawal).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to reject withdrawal", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Withdrawal rejected", withdrawal)
}
