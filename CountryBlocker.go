package main

import (
	"net"

	"github.com/gin-gonic/gin"
)

var blockedCIDRs []*net.IPNet

// InitBlockedCountries loads CIDR blocks at startup
func InitBlockedCountries() {
	cidrs := []string{
		"220.192.0.0/12",   // China Unicom
		"103.55.129.0/24",  // Powerline HK
		"185.226.197.0/24", // Internet Census Group - Netherlands

		// Add more Chinese blocks here
		// "218.0.0.0/8",
		// "221.0.0.0/8",

		// Switzerland blocks (if needed)
		// "194.150.0.0/15",
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("Invalid CIDR: " + cidr)
		}
		blockedCIDRs = append(blockedCIDRs, ipnet)
	}
}

// CountryBlocked middleware checks if request IP is from blocked country
func CountryBlocked() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		ip := net.ParseIP(clientIP)

		if ip == nil {
			// This shouldn't happen in normal operation
			// Could be: malformed headers, attack attempt, or config issue
			c.AbortWithStatus(400)
			return
		}

		for _, cidr := range blockedCIDRs {
			if cidr.Contains(ip) {
				// Option 3: Just close connection (most aggressive)
				c.AbortWithStatus(403)

				c.Abort()
				return
			}
		}

		c.Next()
	}
}
