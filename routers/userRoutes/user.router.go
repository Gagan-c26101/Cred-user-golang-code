package userProfileRoutes

import (
	userProfileController "fib/controllers/userControllers"
	"fib/middleware"
	userPorfileValidator "fib/validators/userValidator"

	"github.com/gofiber/fiber/v2"
)

func SetupUserRoutes(app *fiber.App) {
	userGroup := app.Group("/user")

	userGroup.Post("/add/bank/account", userPorfileValidator.AddBankAccount(), middleware.JWTMiddleware, userProfileController.AddBankAccount)
	userGroup.Post("/send/adhar/otp", userPorfileValidator.SendAdharOtp(), middleware.JWTMiddleware, userProfileController.SendAdharOtp)
	userGroup.Post("/verify/adhar/otp", userPorfileValidator.VerifyAdharOtp(), middleware.JWTMiddleware, userProfileController.VerifyAdharOtp)
	userGroup.Post("/pan/adhar/link/status", userProfileController.PanLinkStatus)

	userGroup.Get("/wallet/balance", middleware.JWTMiddleware, userProfileController.GetFiatWalletBalance)
	userGroup.Post("/deposit/request", userPorfileValidator.ValidateFiatDeposit(), middleware.JWTMiddleware, userProfileController.RequestFiatDeposit)
	userGroup.Get("/deposit/history", middleware.JWTMiddleware, userProfileController.UserFiatDepositHistory)
	userGroup.Post("/withdraw/request", userPorfileValidator.ValidateFiatDeposit(), middleware.JWTMiddleware, userProfileController.RequestFiatWithdrawal)

}
