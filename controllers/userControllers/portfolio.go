package userController

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"fib/database"
	"fib/models"

	"github.com/gofiber/fiber/v2"
)

var priceCache = struct {
	sync.RWMutex
	data map[string]float64
}{data: make(map[string]float64)}

func GetCryptoPrice(coin string) (float64, error) {
	priceCache.RLock()
	if price, found := priceCache.data[coin]; found {
		priceCache.RUnlock()
		return price, nil
	}
	priceCache.RUnlock()

	url := fmt.Sprintf("https://api.binance.com/api/v3/ticker/price?symbol=%sUSDT", coin)
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Price string `json:"price"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	var price float64
	fmt.Sscanf(result.Price, "%f", &price)

	// Update cache
	priceCache.Lock()
	priceCache.data[coin] = price
	priceCache.Unlock()

	return price, nil
}

func UpdateProfitLoss() {
	var portfolios []models.Portfolio
	if err := database.Database.Db.Find(&portfolios).Error; err != nil {
		log.Println("Error fetching portfolios:", err)
		return
	}

	priceMap := make(map[string]float64)

	for _, portfolio := range portfolios {
		if _, exists := priceMap[portfolio.Coin]; !exists {
			price, err := GetCryptoPrice(portfolio.Coin)
			if err != nil {
				log.Println("Error fetching price for", portfolio.Coin, ":", err)
				continue
			}
			priceMap[portfolio.Coin] = price
		}
	}

	tx := database.Database.Db.Begin()
	for _, portfolio := range portfolios {
		currentPrice, found := priceMap[portfolio.Coin]
		if !found {
			continue
		}

		profitLoss := (currentPrice - portfolio.AvgBuyPrice) * portfolio.TotalAmount
		profitLossPercentage := ((currentPrice - portfolio.AvgBuyPrice) / portfolio.AvgBuyPrice) * 100

		if err := tx.Model(&models.Portfolio{}).
			Where("id = ?", portfolio.ID).
			Updates(map[string]interface{}{
				"profit_loss":            profitLoss,
				"profit_loss_percentage": profitLossPercentage,
			}).Error; err != nil {
			log.Println("Error updating profit/loss for", portfolio.Coin, ":", err)
			tx.Rollback()
			return
		}

	}
	tx.Commit()
}

func StartProfitLossUpdater() {
	go func() {
		for {
			fmt.Println("Updating profit/loss for all users...")
			UpdateProfitLoss()
			time.Sleep(30 * time.Second)
		}
	}()
}

// GetPortfolio retrieves a user's portfolio

func GetPortfolio(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	var portfolios []models.Portfolio
	if err := database.Database.Db.Where("user_id = ?", userID).Find(&portfolios).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch portfolio"})
	}

	if len(portfolios) == 0 {
		return c.JSON([]fiber.Map{})
	}

	coins := make(map[string]struct{})
	for _, portfolio := range portfolios {
		coins[portfolio.Coin] = struct{}{}
	}

	priceMap := make(map[string]float64)
	for coin := range coins {
		price, err := GetCryptoPrice(coin)
		if err != nil {
			log.Println("Error fetching price for", coin, ":", err)
			continue
		}
		priceMap[coin] = price
	}

	response := []fiber.Map{}
	for _, portfolio := range portfolios {
		currentPrice, found := priceMap[portfolio.Coin]
		if !found {
			continue
		}

		profitLoss := (currentPrice - portfolio.AvgBuyPrice) * portfolio.TotalAmount
		profitLossPercentage := ((currentPrice - portfolio.AvgBuyPrice) / portfolio.AvgBuyPrice) * 100

		response = append(response, fiber.Map{
			"coin":                   portfolio.Coin,
			"total_amount":           portfolio.TotalAmount,
			"avg_buy_price":          portfolio.AvgBuyPrice,
			"current_price":          currentPrice,
			"profit_loss":            profitLoss,
			"profit_loss_percentage": profitLossPercentage,
		})
	}

	return c.JSON(response)
}
