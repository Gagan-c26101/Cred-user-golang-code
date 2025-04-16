package authValidator

import (
	"fib/middleware"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Helper to validate email format
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// Helper to validate mobile number format
func isValidMobile(mobile string) bool {
	re := regexp.MustCompile(`^\d{10}$`)
	return re.MatchString(mobile)
}

// Signup validator middleware
func Signup() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// user := new(models.User)
		reqData := new(struct {
			Mobile   string `json:"mobile"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Name     string `json:"name"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		errors := make(map[string]string)

		// Validate Name
		if len(strings.TrimSpace(reqData.Name)) < 5 {
			errors["name"] = "Name must be at least 5 characters long!"
		}

		// Validate Email
		if reqData.Email == "" || !isValidEmail(reqData.Email) {
			errors["email"] = "Invalid email!"
		}

		// Validate Mobile
		if reqData.Mobile == "" || !isValidMobile(reqData.Mobile) {
			errors["mobile"] = "Invalid mobile number!"
		}

		// Validate Password
		if len(strings.TrimSpace(reqData.Password)) < 8 {
			errors["password"] = "Password must be at least 8 characters long!"
		}

		// Respond with errors if any exist
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		// Pass validated user to the next middleware
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// Login validator middleware
func Login() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile   string `json:"mobile"`
			Email    string `json:"email"`
			Password string `json:"password"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		errors := make(map[string]string)

		// Validate credentials
		if reqData.Email == "" && reqData.Mobile == "" {
			errors["credentials"] = "Either email or mobile number is required!"
		} else {
			if reqData.Email != "" && !isValidEmail(reqData.Email) {
				errors["email"] = "Invalid email!"
			}
			if reqData.Mobile != "" && !isValidMobile(reqData.Mobile) {
				errors["mobile"] = "Invalid mobile number!"
			}
		}

		// Validate Password
		if len(strings.TrimSpace(reqData.Password)) < 8 {
			errors["password"] = "Password must be at least 8 characters long!"
		}

		// Respond with errors if any exist
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		// Pass validated login request to the next middleware
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// SendOTP validator middleware
func SendOTP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile string `json:"mobile"`
			Email  string `json:"email"`
		})

		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		errors := make(map[string]string)

		// Validate credentials
		if reqData.Email == "" && reqData.Mobile == "" {
			errors["credentials"] = "Either email or mobile number is required!"
		} else {
			if reqData.Email != "" && !isValidEmail(reqData.Email) {
				errors["email"] = "Invalid email!"
			}
			if reqData.Mobile != "" && !isValidMobile(reqData.Mobile) {
				errors["mobile"] = "Invalid mobile number!"
			}
		}

		// Respond with errors if any exist
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		// Pass validated login request to the next middleware
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// VerifyOTP validates OTP request data
func VerifyOTP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile string `json:"mobile"`
			Email  string `json:"email"`
			Code   string `json:"code"`
		})

		// Parse the request body into reqData
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		// Initialize a map to collect validation errors
		errors := make(map[string]string)

		// Validate that either email or mobile is provided
		if reqData.Email == "" && reqData.Mobile == "" {
			errors["credentials"] = "Either email or mobile number is required!"
		} else {
			// Validate email if provided
			if reqData.Email != "" && !isValidEmail(reqData.Email) {
				errors["email"] = "Invalid email!"
			}

			// Validate mobile number if provided
			if reqData.Mobile != "" && !isValidMobile(reqData.Mobile) {
				errors["mobile"] = "Invalid mobile number!"
			}
		}

		// Validate OTP code
		if reqData.Code == "" {
			errors["code"] = "OTP code is required!"
		}

		// If validation errors exist, return them
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		// Store validated data and pass to the next middleware
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// ResetPassword validator middleware
func ResetPassword() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Password string `json:"password"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		errors := make(map[string]string)

		// Validate Password
		if len(strings.TrimSpace(reqData.Password)) < 8 {
			errors["password"] = "Password must be at least 8 characters long!"
		}

		// Respond with errors if any exist
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		// Pass validated login request to the next middleware
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// Validate new mobile/email input
func ChangeMobileEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			NewMobile string `json:"new_mobile"`
			NewEmail  string `json:"new_email"`
		})

		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}

		errors := make(map[string]string)

		// Validate new email or mobile
		if reqData.NewEmail == "" && reqData.NewMobile == "" {
			errors["new_contact"] = "New mobile or email is required!"
		} else {
			if reqData.NewEmail != "" && !isValidEmail(reqData.NewEmail) {
				errors["new_email"] = "Invalid email format!"
			}
			if reqData.NewMobile != "" && !isValidMobile(reqData.NewMobile) {
				errors["new_mobile"] = "Invalid mobile format!"
			}
		}

		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}
