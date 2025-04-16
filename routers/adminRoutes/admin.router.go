package adminRoutes

import (
	userProfileController "fib/controllers/userControllers"
	"fib/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupAdminRoutes(app *fiber.App) {
	adminGroup := app.Group("/admin")

	adminGroup.Put("/admin/deposit/approve/:id", middleware.Admin, userProfileController.ApproveFiatDeposit)
	adminGroup.Put("/admin/withdraw/approve/:id", middleware.Admin, userProfileController.ApproveFiatWithdrawal)
	adminGroup.Put("/admin/withdraw/reject/:id", middleware.Admin, userProfileController.RejectFiatWithdrawal)

}
