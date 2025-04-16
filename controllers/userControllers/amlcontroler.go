package userController

import (
	"log"
	"strconv"
	"time"

	"fib/database"
	"fib/models"

	"github.com/gofiber/fiber/v2"
)

func CreateAmlData(c *fiber.Ctx) error {
	amlData := new(models.AmlUserData)
	if err := c.BodyParser(amlData); err != nil {
		log.Println("Error parsing request body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	amlData.CreatedAt = time.Now()
	amlData.UpdatedAt = time.Now()

	if err := database.Database.Db.Create(amlData).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not create AML data"})
	}

	return c.Status(fiber.StatusCreated).JSON(amlData)
}

// GetAmlDataById fetches a single AML record by ID
func GetAmlDataById(c *fiber.Ctx) error {
	User_id := c.Params("User_id")
	var amlData models.AmlUserData

	if err := database.Database.Db.First(&amlData, "id = ?", User_id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "AML data not found"})
	}

	return c.JSON(amlData)
}

// UpdateAmlData updates an existing AML record
func UpdateAmlData(c *fiber.Ctx) error {
	User_id := c.Params("User_id")
	var amlData models.AmlUserData

	if err := database.Database.Db.First(&amlData, "id = ?", User_id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "AML data not found"})
	}

	if err := c.BodyParser(&amlData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	amlData.UpdatedAt = time.Now()

	if err := database.Database.Db.Save(&amlData).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not update AML data"})
	}

	return c.JSON(amlData)
}

// DeleteAmlData deletes an AML record
func DeleteAmlData(c *fiber.Ctx) error {
	User_id := c.Params("User_id")

	if err := database.Database.Db.Delete(&models.AmlUserData{}, "id = ?", User_id).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not delete AML data"})
	}

	return c.JSON(fiber.Map{"message": "AML data deleted successfully"})
}

// GetAllAml fetches all AML records with pagination
func GetAllAml(c *fiber.Ctx) error {
	var amlData []models.AmlUserData
	var count int64

	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	page, _ := strconv.Atoi(c.Query("page", "1"))
	offset := (page - 1) * limit

	database.Database.Db.Model(&models.AmlUserData{}).Count(&count)
	if err := database.Database.Db.Limit(limit).Offset(offset).Order("created_at DESC").Find(&amlData).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not retrieve AML data"})
	}

	return c.JSON(fiber.Map{
		"message": "Successfully retrieved AML data",
		"count":   count,
		"result":  amlData,
	})
}
