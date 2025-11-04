package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func main() {

	// Initialize 404 Limiter Middleware
	tracker := NewIP404Tracker(
		3,             // threshold: 3 404s
		1*time.Minute, // window: within 1 minute
		24*time.Hour,  // banDuration: ban for 24 hours
	)

	// Prepare router
	router := gin.Default()

	// 404 Limiter Middleware
	router.Use(tracker.Middleware())

	// Start Server
	router.Run(":8080")
}
