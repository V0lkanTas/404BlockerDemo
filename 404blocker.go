package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// IP404Tracker tracks 404 responses by IP address
type IP404Tracker struct {
	// Map to track 404 counts by IP
	counts map[string][]time.Time

	// Map to track shadow-banned IPs and when they can be unbanned
	bannedUntil map[string]time.Time

	// Set of whitelisted IPs that are exempt from tracking/banning
	whitelist map[string]bool

	// Mutex for thread safety
	mu sync.RWMutex

	// Banned Request counter
	bannedRequest map[string]int

	// Configuration
	threshold   int           // Number of 404s allowed in window
	window      time.Duration // Time window to count 404s
	banDuration time.Duration // How long to shadow ban
}

// NewIP404Tracker creates a new tracker with the specified settings
func NewIP404Tracker(threshold int, window, banDuration time.Duration) *IP404Tracker {
	tracker := &IP404Tracker{
		counts:        make(map[string][]time.Time),
		bannedUntil:   make(map[string]time.Time),
		whitelist:     make(map[string]bool),
		bannedRequest: make(map[string]int), // Don't forget to initialize this!
		threshold:     threshold,
		window:        window,
		banDuration:   banDuration,
	}
	// Add hardcoded IPs to whitelist
	tracker.initializeWhitelist()
	// Start a background goroutine to clean up expired entries
	go tracker.cleanupLoop()
	// Start hourly logging of banned requests
	go tracker.startBannedRequestLogger()

	return tracker
}

// initializeWhitelist adds hardcoded IPs to the whitelist
func (t *IP404Tracker) initializeWhitelist() {
	// Add your testing/admin IPs here
	hardcodedWhitelist := []string{
		"1.1.1.1", // Replace with your DEV Machine IP
		// Add more IPs as needed
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, ip := range hardcodedWhitelist {
		t.whitelist[ip] = true
	}
}

// AddToWhitelist adds an IP to the whitelist
func (t *IP404Tracker) AddToWhitelist(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.whitelist[ip] = true
}

// RemoveFromWhitelist removes an IP from the whitelist
func (t *IP404Tracker) RemoveFromWhitelist(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.whitelist, ip)
}

// IsWhitelisted checks if an IP is in the whitelist
func (t *IP404Tracker) IsWhitelisted(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.whitelist[ip]
}

// GetWhitelist returns a copy of the current whitelist
func (t *IP404Tracker) GetWhitelist() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var ips []string
	for ip := range t.whitelist {
		ips = append(ips, ip)
	}
	return ips
}

// cleanupLoop periodically removes expired entries to prevent memory leaks
func (t *IP404Tracker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes expired counts and bans
func (t *IP404Tracker) cleanup() {
	now := time.Now()
	windowCutoff := now.Add(-t.window)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Clean up expired 404 counts
	for ip, timestamps := range t.counts {
		var validTimestamps []time.Time
		for _, ts := range timestamps {
			if ts.After(windowCutoff) {
				validTimestamps = append(validTimestamps, ts)
			}
		}
		if len(validTimestamps) == 0 {
			delete(t.counts, ip)
		} else {
			t.counts[ip] = validTimestamps
		}
	}

	// Clean up expired bans
	for ip, bannedUntil := range t.bannedUntil {
		if bannedUntil.Before(now) {
			delete(t.bannedUntil, ip)
		}
	}
}

// Record404 records a 404 for the given IP and returns true if the IP is now banned
func (t *IP404Tracker) Record404(ip string) bool {
	// Skip tracking for whitelisted IPs
	if t.IsWhitelisted(ip) {
		return false
	}

	now := time.Now()
	windowStart := now.Add(-t.window)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if already banned
	if banTime, exists := t.bannedUntil[ip]; exists && banTime.After(now) {
		return true // Already banned
	}

	// Add current timestamp to the IP's record
	timestamps := t.counts[ip]

	// Filter out timestamps outside the window
	var recentTimestamps []time.Time
	for _, ts := range timestamps {
		if ts.After(windowStart) {
			recentTimestamps = append(recentTimestamps, ts)
		}
	}

	// Add the new timestamp
	recentTimestamps = append(recentTimestamps, now)
	t.counts[ip] = recentTimestamps

	// Check if threshold exceeded
	if len(recentTimestamps) > t.threshold {
		// Ban the IP
		t.bannedUntil[ip] = now.Add(t.banDuration)
		return true
	}

	return false
}

// IsBanned checks if an IP is currently banned
func (t *IP404Tracker) IsBanned(ip string) bool {
	// Whitelisted IPs are never banned
	if t.IsWhitelisted(ip) {
		return false
	}

	now := time.Now()

	t.mu.RLock()
	defer t.mu.RUnlock()

	banTime, exists := t.bannedUntil[ip]
	return exists && banTime.After(now)
}

// UnbanIP manually removes an IP from the ban list (useful for admin functions)
func (t *IP404Tracker) UnbanIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.bannedUntil, ip)
}

// GetBannedIPs returns a map of currently banned IPs and their ban expiry times
func (t *IP404Tracker) GetBannedIPs() map[string]time.Time {
	now := time.Now()

	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]time.Time)
	for ip, banTime := range t.bannedUntil {
		if banTime.After(now) {
			result[ip] = banTime
		}
	}

	return result
}

func (t *IP404Tracker) BannedRequestCounter(clientIP string) {
	t.mu.Lock()
	t.bannedRequest[clientIP]++
	t.mu.Unlock()
}

// startBannedRequestLogger prints banned request counts to stdout every hour
func (t *IP404Tracker) startBannedRequestLogger() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.RLock()
		fmt.Println("=== Banned Requests Report ===")
		fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))
		if len(t.bannedRequest) == 0 {
			fmt.Println("No banned requests recorded")
		} else {
			for ip, count := range t.bannedRequest {
				fmt.Printf("IP: %s - Banned Requests: %d\n", ip, count)
			}
		}
		fmt.Println("==============================")
		t.mu.RUnlock()
	}
}

// Middleware returns a Gin middleware that tracks 404s and shadow bans IPs
func (t *IP404Tracker) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Check if the IP is already banned (whitelisted IPs will return false)
		if t.IsBanned(clientIP) {
			// For shadow banning, we don't tell the client they're banned
			// Instead, we just serve a generic 404 response
			c.Status(404)
			c.Abort()
			return
		}

		// Process the request
		c.Next()

		// Check if this was a 404 response
		if c.Writer.Status() == 404 {
			// Record the 404 and check if IP should be banned
			// (whitelisted IPs won't be tracked or banned)
			if t.Record404(clientIP) {
				// IP is now banned, but we've already sent the response
				// so we'll just log it for now
				// You could add zerolog logging here
			}
		}
	}
}
