package database

import (
	"fib/config"
	"fib/models"
	"log"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	// "gorm.io/gorm/logger"
)

// DbInstance struct holds the database connection instance
type DbInstance struct {
	Db *gorm.DB
}

// Database is the global database instance
var Database DbInstance

// ConnectDb establishes a connection to the database
func ConnectDb() {
	// Get database name from configuration
	dbName := config.AppConfig.DBName

	// Open database connection
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to the database '%s': %v", dbName, err)
		os.Exit(2)
	}

	log.Printf("Connected Successfully to Database: %s\n", dbName)

	// Set GORM logger to Info mode
	// db.Logger = logger.Default.LogMode(logger.Info)

	// Run database migrations
	runMigrations(db)

	// Save database instance globally
	Database = DbInstance{
		Db: db,
	}
}

// runMigrations performs database migrations
func runMigrations(db *gorm.DB) {
	log.Println("Running Migrations")
	if err := db.AutoMigrate(&models.User{}, &models.BankDetails{},
		&models.UserKYC{}, &models.OTP{}, &models.LoginTracking{}, &models.ContactChangeTracking{}, &models.FiatDeposit{},
		&models.CryptoDeposit{}, &models.UserFiatWallet{}); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
}
