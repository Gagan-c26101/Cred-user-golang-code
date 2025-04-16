package authRoutes

import (
	controllers "fib/controllers/auth"
	"fib/middleware"
	validators "fib/validators/auth"

	"github.com/gofiber/fiber/v2"
)

func SetupAuthRoutes(app *fiber.App) {
	authGroup := app.Group("/auth")

	authGroup.Post("/signup", validators.Signup(), controllers.Signup)
	authGroup.Post("/login", validators.Login(), controllers.Login)
	authGroup.Post("/send/otp", validators.SendOTP(), controllers.SendOTP)
	authGroup.Patch("/verify/otp", validators.VerifyOTP(), controllers.VerifyOTP)
	authGroup.Post("/forgot/password/send/otp", validators.SendOTP(), controllers.ForgotPasswordSendOTP)
	authGroup.Patch("/forgot/password/verify/otp", validators.VerifyOTP(), controllers.ForgotPasswordVerifyOTP)
	authGroup.Patch("/reset/password", validators.ResetPassword(), middleware.JWTMiddleware, controllers.ResetPassword)

	authGroup.Post("/change-mobile-email/send-old-otp", middleware.JWTMiddleware, controllers.SendOldOTP)
	authGroup.Post("/change-mobile-email/verify-old-otp", middleware.JWTMiddleware, controllers.VerifyOldOTP)
	authGroup.Post("/change-mobile-email/send-new-otp", middleware.JWTMiddleware, validators.ChangeMobileEmail(), controllers.SendNewOTP)
	authGroup.Post("/change-mobile-email/verify-new-otp", middleware.JWTMiddleware, controllers.VerifyNewOTP)
}
