package authController

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fib/config"
	"fib/database"
	"fib/middleware"
	"fib/models"
	"fib/utils"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func generateReferralCode() string {
	const charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 6

	// Function to check if the referral code already exists in the database
	checkReferralCodeExists := func(code string) bool {
		var user models.User
		result := database.Database.Db.Where("referral_code = ?", code).First(&user)
		return result.RowsAffected > 0
	}

	for {
		// Create a slice to hold the generated characters
		code := make([]byte, length)

		// Generate random characters
		for i := 0; i < length; i++ {
			// Generate a random index within the charSet
			randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
			if err != nil {
				log.Fatal("Failed to generate random number:", err)
			}

			// Assign the random character to the code slice
			code[i] = charSet[randomIndex.Int64()]
		}

		// Convert byte slice to string
		referralCode := string(code)

		// Check if the generated referral code already exists in the database
		if !checkReferralCodeExists(referralCode) {
			return referralCode // Return the code if it doesn't exist
		}
	}
}

func Signup(c *fiber.Ctx) error {
	user := new(models.User)
	if err := c.BodyParser(user); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
	}

	// Check if email already exists
	existingUser := models.User{}
	result := database.Database.Db.Where("email = ?", user.Email).First(&existingUser)
	if result.RowsAffected > 0 {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Email is already registered!", nil)
	}

	// Check if mobile already exists
	existingUserByMobile := models.User{}
	result = database.Database.Db.Where("mobile = ?", user.Mobile).First(&existingUserByMobile)
	if result.RowsAffected > 0 {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Mobile number is already registered!", nil)
	}

	user.ReferralCode = generateReferralCode()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), config.AppConfig.SaltRound)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to process your request!", nil)
	}
	user.Password = string(hashedPassword)

	if err := database.Database.Db.Create(user).Error; err != nil {
		log.Printf("Error saving user to database: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to Signup user!", nil)
	}

	user.Password = ""

	return middleware.JsonResponse(c, fiber.StatusCreated, true, "User registered successfully.", user)
}

func Login(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile   string `json:"mobile"`
		Email    string `json:"email"`
		Password string `json:"password"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	var user models.User
	var result *gorm.DB

	// Retrieve user by email or mobile
	if reqData.Email != "" {
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
	} else {
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
	}

	if result.Error != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid credentials!", nil)
	}

	if !user.IsEmailVerified {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Email not verified!", nil)
	}

	if !user.IsMobileVerified {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Mobile not verified!", nil)
	}

	// Check if the user is blocked
	if user.IsBlocked && user.BlockedUntil != nil && user.BlockedUntil.After(time.Now()) {

		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Your account is temporarily blocked. Try again later.", nil)
	}

	if user.LastFailedLogin != nil && time.Since(*user.LastFailedLogin) > 15*time.Minute {

		user.FailedLoginAttempts = 0
		user.LastFailedLogin = nil
		database.Database.Db.Save(&user)
	}

	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqData.Password)); err != nil {

		user.FailedLoginAttempts++
		now := time.Now()
		user.LastFailedLogin = &now

		// Block user after 3 failed attempts
		if user.FailedLoginAttempts >= 3 {
			user.IsBlocked = true

			unblockTime := now.Add(1 * time.Minute)
			user.BlockedUntil = &unblockTime

			if err := database.Database.Db.Save(&user).Error; err != nil {
				log.Printf("Error blocking user: %v", err)
			}
		}

		// Save the updated user details
		database.Database.Db.Save(&user)

		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Wrong Password", nil)
	}

	// Update last login time
	user.LastLogin = time.Now()
	user.FailedLoginAttempts = 0 // Reset failed login attempts after successful login
	user.IsBlocked = false
	if err := database.Database.Db.Save(&user).Error; err != nil {
		log.Printf("Error saving last login time: %v", err)
	}

	ip := c.IP()
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	userAgent := c.Get("User-Agent")

	log.Printf("Login attempt: User-Agent: %s, IP Address: %s", userAgent, ip)

	// Capture login tracking details
	loginTracking := models.LoginTracking{
		UserID:    user.ID,
		IPAddress: ip,
		Device:    userAgent,
		Timestamp: time.Now(),
	}

	// Log the user login tracking
	log.Printf("User %d logged in from IP: %s", user.ID, loginTracking.IPAddress)

	if err := database.Database.Db.Create(&loginTracking).Error; err != nil {
		log.Printf("Error saving login tracking details: %v", err)
	}

	// Sanitize user data (remove sensitive fields)
	user.Password = ""
	user.ProfileImage = ""

	// Generate JWT token
	token, err := middleware.GenerateJWT(user.ID, user.Name, user.Role)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Error generating JWT token!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Login successful.", fiber.Map{
		"user":  user,
		"token": token,
	})
}

func SendOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	// Check if email or mobile is already verified
	var user models.User
	var result *gorm.DB

	if reqData.Email != "" {
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid email!", nil)
		}
		if user.IsEmailVerified {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Email already verified!", nil)
		}
	} else {
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid mobile!", nil)
		}
		if user.IsMobileVerified {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Mobile already verified!", nil)
		}
	}

	// Generate OTP
	otp := utils.GenerateOTP()

	// Set OTP expiration time (e.g., 5 minutes from now)
	expiresAt := time.Now().Add(5 * time.Minute)

	// Create OTP record
	otpRecord := models.OTP{
		UserID:      user.ID,
		Email:       reqData.Email,
		Mobile:      reqData.Mobile,
		Code:        otp,
		ExpiresAt:   expiresAt,
		Description: "Email/Mobile Verification OTP",
	}

	// Send OTP via SMS if mobile is provided
	if reqData.Mobile != "" {
		if err := utils.SendOTPToMobile(reqData.Mobile, otp); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to mobile!", nil)
		}
	}

	// Send OTP via email if email is provided
	if reqData.Email != "" {
		if err := utils.SendOTPEmail(otp, reqData.Email); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to email!", nil)
		}
	}

	// Save OTP record to the database
	if err := database.Database.Db.Create(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to Create OTP!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent successfully.", nil)
}

func VerifyOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})

	// Parse the request body
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	var user models.User
	var otpRecord models.OTP
	var result *gorm.DB

	// Retrieve user and OTP record based on email or mobile
	if reqData.Email != "" {
		// Find user by email
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the email
		result = database.Database.Db.Where("email = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Email, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	} else {
		// Find user by mobile
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the mobile
		result = database.Database.Db.Where("mobile = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Mobile, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	}

	// Check if OTP has expired
	if otpRecord.ExpiresAt.Before(time.Now()) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "OTP has expired!", nil)
	}

	// Mark OTP as used
	otpRecord.IsUsed = true
	if err := database.Database.Db.Save(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update OTP status!", nil)
	}

	// Update user's verification status based on email or mobile
	if reqData.Email != "" {
		user.IsEmailVerified = true
	} else {
		user.IsMobileVerified = true
	}

	// Save updated user verification status
	if err := database.Database.Db.Save(&user).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update user verification status!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP verified successfully!", nil)
}

func ForgotPasswordSendOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	// Check if email or mobile is already verified
	var user models.User
	var result *gorm.DB

	if reqData.Email != "" {
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid email credentials!", nil)
		}
	} else {
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid mobile credentials!", nil)
		}
	}

	// Generate OTP
	otp := utils.GenerateOTP()

	// Set OTP expiration time (e.g., 5 minutes from now)
	expiresAt := time.Now().Add(5 * time.Minute)

	// Create OTP record
	otpRecord := models.OTP{
		UserID:      user.ID,
		Email:       reqData.Email,
		Mobile:      reqData.Mobile,
		Code:        otp,
		ExpiresAt:   expiresAt,
		Description: "Forgot Password OTP",
	}

	// Send OTP via SMS if mobile is provided
	if reqData.Mobile != "" {
		if err := utils.SendOTPToMobile(reqData.Mobile, otp); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to mobile!", nil)
		}
	}

	// Send OTP via email if email is provided
	if reqData.Email != "" {
		if err := utils.SendOTPEmail(otp, reqData.Email); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to email!", nil)
		}
	}

	// Save OTP record to the database
	if err := database.Database.Db.Create(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to Create OTP!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent successfully.", nil)
}

func ForgotPasswordVerifyOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})

	// Parse the request body
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	var user models.User
	var otpRecord models.OTP
	var result *gorm.DB

	// Retrieve user and OTP record based on email or mobile
	if reqData.Email != "" {
		// Find user by email
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the email
		result = database.Database.Db.Where("email = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Email, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	} else {
		// Find user by mobile
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the mobile
		result = database.Database.Db.Where("mobile = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Mobile, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	}

	// Check if OTP has expired
	if otpRecord.ExpiresAt.Before(time.Now()) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "OTP has expired!", nil)
	}

	// Mark OTP as used
	otpRecord.IsUsed = true
	if err := database.Database.Db.Save(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update OTP status!", nil)
	}

	// Generate JWT token
	token, err := middleware.GenerateJWT(user.ID, user.Name, user.Role)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Error generating JWT token!", nil)
	}

	// Return success response along with the JWT token
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Now You can reset your password.", fiber.Map{
		"token": token,
	})
}

func ResetPassword(c *fiber.Ctx) error {
	// Retrieve the userId from the JWT token (added by JWTMiddleware)
	userId := c.Locals("userId").(uint)

	fmt.Println(userId)

	// Parse the request body to get the new password
	reqData := new(struct {
		Password string `json:"password"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	// Retrieve the user from the database using userId from JWT token
	var user models.User

	result := database.Database.Db.Where("id = ? AND is_deleted = ?", userId, false).First(&user)

	if result.Error != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found or invalid credentials!", nil)
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(reqData.Password), config.AppConfig.SaltRound)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to hash password!", nil)
	}

	// Update the user's password in the database
	user.Password = string(hashedPassword)
	if err := database.Database.Db.Save(&user).Error; err != nil {
		log.Printf("Error updating user password: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update password!", nil)
	}

	// Respond with success message and the new JWT token
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Password reset successfully.", nil)
}

// Change of mobile or email

func SendOldOTP(c *fiber.Ctx) error {

	userId, ok := c.Locals("userId").(uint)
	if !ok || userId == 0 {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized: login required", nil)
	}

	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body", nil)
	}

	if reqData.Email == "" && reqData.Mobile == "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Email or Mobile is required!", nil)
	}

	var user models.User
	if err := database.Database.Db.Where("(email = ? OR mobile = ?) AND is_deleted = ?", reqData.Email, reqData.Mobile, false).First(&user).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
	}
	if (reqData.Email != "" && reqData.Email != user.Email) || (reqData.Mobile != "" && reqData.Mobile != user.Mobile) {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Provided email or mobile does not match your registered details!", nil)
	}

	// Generate OTP
	otp := utils.GenerateOTP()
	expiresAt := time.Now().Add(5 * time.Minute)

	// Save or update OTP
	otpRecord := models.OTP{
		UserID:      user.ID,
		Email:       reqData.Email,
		Mobile:      reqData.Mobile,
		Code:        otp,
		ExpiresAt:   expiresAt,
		Description: "Verification old OTP",
		IsUsed:      false,
		IsDeleted:   false,
	}

	if reqData.Mobile != "" {
		if err := utils.SendOTPToMobile(reqData.Mobile, otp); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to mobile!", nil)
		}
	}

	// Send OTP via email if email is provided
	if reqData.Email != "" {
		if err := utils.SendOTPEmail(otp, reqData.Email); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP to email!", nil)
		}
	}

	// Save OTP record to the database
	if err := database.Database.Db.Create(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to Create OTP!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent successfully.", nil)
}

func VerifyOldOTP(c *fiber.Ctx) error {

	userId, ok := c.Locals("userId").(uint)
	if !ok || userId == 0 {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized: login required", nil)
	}

	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})

	// Parse the request body
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	var user models.User
	var otpRecord models.OTP
	var result *gorm.DB

	// Retrieve user and OTP record based on email or mobile
	if reqData.Email != "" {
		// Find user by email
		result = database.Database.Db.Where("email = ? AND is_deleted = ?", reqData.Email, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the email
		result = database.Database.Db.Where("email = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Email, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	} else {
		// Find user by mobile
		result = database.Database.Db.Where("mobile = ? AND is_deleted = ?", reqData.Mobile, false).First(&user)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
		}

		// Find the OTP record for the mobile
		result = database.Database.Db.Where("mobile = ? AND code = ? AND is_used = ? AND is_deleted = ?", reqData.Mobile, reqData.Code, false, false).First(&otpRecord)
		if result.Error != nil {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP or OTP expired!", nil)
		}
	}

	// Check if OTP has expired
	if otpRecord.ExpiresAt.Before(time.Now()) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "OTP has expired!", nil)
	}

	// Mark OTP as used
	otpRecord.IsUsed = true
	if err := database.Database.Db.Save(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update OTP status!", nil)
	}

	if reqData.Email != "" {
		user.IsEmailVerified = true
	} else {
		user.IsMobileVerified = true
	}

	redisClient := config.GetRedisClient()
	verifiedKey := fmt.Sprintf("verified_old_contact:%d", otpRecord.UserID)
	verifiedData, _ := json.Marshal(reqData)
	err := redisClient.Set(context.Background(), verifiedKey, verifiedData, 10*time.Minute).Err()
	if err != nil {
		log.Printf("Failed to store verified old contact in Redis: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to process verification!", nil)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Old contact verified", nil)
}

func SendNewOTP(c *fiber.Ctx) error {
	userID, ok := c.Locals("userId").(uint)
	if !ok {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized!", nil)
	}

	reqData := new(struct {
		NewEmail  string `json:"new_email"`
		NewMobile string `json:"new_mobile"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	if reqData.NewEmail == "" && reqData.NewMobile == "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "New email or mobile is required!", nil)
	}

	redisClient := config.GetRedisClient()
	verifiedKey := fmt.Sprintf("verified_old_contact:%d", userID)
	verifiedData, err := redisClient.Get(context.Background(), verifiedKey).Result()
	if err == redis.Nil {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Old contact verification required!", nil)
	} else if err != nil {
		log.Printf("Failed to retrieve verification from Redis: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to verify old contact!", nil)
	}
	log.Printf("Verified old contact: %s", verifiedData)

	// Check if new email or mobile is already in use
	var existingUser models.User
	if reqData.NewEmail != "" && database.Database.Db.Where("email = ?", reqData.NewEmail).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Email already in use!", nil)
	}
	if reqData.NewMobile != "" && database.Database.Db.Where("mobile = ?", reqData.NewMobile).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Mobile already in use!", nil)
	}

	// Generate OTP
	otp := utils.GenerateOTP()
	expiresAt := time.Now().Add(5 * time.Minute)

	// Save OTP only, without storing new email/mobile
	otpRecord := models.OTP{
		UserID:      userID,
		Code:        otp,
		ExpiresAt:   expiresAt,
		Description: "Verify new email/mobile before updating",
	}

	if err := database.Database.Db.Create(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to create OTP!", nil)
	}

	// Send OTP (passing new email or mobile directly without saving in DB)
	if reqData.NewEmail != "" {
		utils.SendOTPEmail(otp, reqData.NewEmail)
	} else {
		utils.SendOTPToMobile(reqData.NewMobile, otp)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent to new email/mobile.", nil)
}

func VerifyNewOTP(c *fiber.Ctx) error {
	userID, ok := c.Locals("userId").(uint)
	if !ok {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized!", nil)
	}

	reqData := new(struct {
		Code      string `json:"code"`
		NewEmail  string `json:"new_email"`
		NewMobile string `json:"new_mobile"`
	})

	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}

	if reqData.Code == "" || (reqData.NewEmail == "" && reqData.NewMobile == "") {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "OTP code and new contact (email or mobile) are required!", nil)
	}

	// Retrieve OTP record
	var otpRecord models.OTP
	if err := database.Database.Db.Where("user_id = ? AND code = ? AND is_used = ? AND is_deleted = ? AND expires_at > ?", userID, reqData.Code, false, false, time.Now()).
		First(&otpRecord).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or expired OTP!", nil)
	}

	// Mark OTP as used
	if err := database.Database.Db.Model(&otpRecord).Update("is_used", true).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update OTP status!", nil)
	}

	var user models.User
	if err := database.Database.Db.Where("id = ?", userID).First(&user).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "User not found!", nil)
	}

	// Validate that the new email or mobile is not already taken
	var existingUser models.User
	if reqData.NewEmail != "" && database.Database.Db.Where("email = ?", reqData.NewEmail).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Email already in use!", nil)
	}
	if reqData.NewMobile != "" && database.Database.Db.Where("mobile = ?", reqData.NewMobile).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Mobile already in use!", nil)
	}

	oldEmail := user.Email
	oldMobile := user.Mobile

	// Update user email or mobile only after successful OTP verification
	updateFields := map[string]interface{}{}
	if reqData.NewEmail != "" {
		updateFields["email"] = reqData.NewEmail
		updateFields["is_email_verified"] = true
	}
	if reqData.NewMobile != "" {
		updateFields["mobile"] = reqData.NewMobile
		updateFields["is_mobile_verified"] = true
	}

	if err := database.Database.Db.Model(&models.User{}).Where("id = ?", userID).Updates(updateFields).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update email or mobile!", nil)
	}

	ip := c.IP()
	userAgent := c.Get("User-Agent")

	// Save change tracking record
	changeLog := models.ContactChangeTracking{
		UserID:    userID,
		OldEmail:  oldEmail,
		NewEmail:  reqData.NewEmail,
		OldMobile: oldMobile,
		NewMobile: reqData.NewMobile,
		ChangedAt: time.Now(),
		IPAddress: ip,
		UserAgent: userAgent,
	}

	if err := database.Database.Db.Create(&changeLog).Error; err != nil {
		log.Printf("Error logging contact change: %v", err)
	}

	return middleware.JsonResponse(c, fiber.StatusOK, true, "Email/Mobile updated successfully!", nil)
}
