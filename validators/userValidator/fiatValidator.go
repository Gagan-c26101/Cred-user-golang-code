package userController

import (
	"fib/middleware"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

var validate = validator.New()

// 🏦 Deposit Input Struct
type FiatDepositRequest struct {
	Amount          float64 `json:"amount" validate:"required,gt=0"`
	Currency        string  `json:"currency" validate:"required"`
	TransactionID   string  `json:"transaction_id" validate:"required"`
	BankPaymentType string  `json:"bank_payment_type" validate:"required"`
	Image           string  `json:"image" validate:"required"`
	Description     string  `json:"description"`
}

// 💸 Withdraw Input Struct
type FiatWithdrawRequest struct {
	Amount      float64 `json:"amount" validate:"required,gt=0"`
	Currency    string  `json:"currency" validate:"required"`
	Remarks     string  `json:"remarks"`
	BankDetails string  `json:"bank_details" validate:"required"`
}

// 🧪 Validator Middleware: Fiat Deposit
func ValidateFiatDeposit() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body FiatDepositRequest
		if err := c.BodyParser(&body); err != nil {
			return middleware.ValidationErrorResponse(c, map[string]string{
				"body": "Invalid request format",
			})
		}
		if err := validate.Struct(&body); err != nil {
			if errs, ok := err.(validator.ValidationErrors); ok {
				errorMap := make(map[string]string)
				for _, e := range errs {
					errorMap[e.Field()] = e.Error()
				}
				return middleware.ValidationErrorResponse(c, errorMap)
			}
			return middleware.ValidationErrorResponse(c, map[string]string{
				"error": err.Error(),
			})
		}
		c.Locals("validatedBody", body)
		return c.Next()
	}
}

func ValidateFiatWithdraw() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body FiatWithdrawRequest
		if err := c.BodyParser(&body); err != nil {
			return middleware.ValidationErrorResponse(c, map[string]string{
				"body": "Invalid request format",
			})
		}
		if err := validate.Struct(&body); err != nil {
			if errs, ok := err.(validator.ValidationErrors); ok {
				errorMap := make(map[string]string)
				for _, e := range errs {
					errorMap[e.Field()] = e.Error()
				}
				return middleware.ValidationErrorResponse(c, errorMap)
			}
			return middleware.ValidationErrorResponse(c, map[string]string{
				"error": err.Error(),
			})
		}
		c.Locals("validatedBody", body)
		return c.Next()
	}
}
