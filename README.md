# 404BlockerDemo
A golang and gingonic example for blocking repated 404 offenders.

This is a great way of increasing difficulty on others trying to understand your systems.

# Example Usage

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


# Example Tests
## Test 1
1) Run the binary
2) start hitting random URLs
 - 127.0.0.1/Test1
 - 127.0.0.1/Test2
 - 127.0.0.1/Test3
 - 127.0.0.1/Test4

You should see your ip address in the blocked list that populates evey 10 seconds

## Test 2
1) Add your ip to the initializeWhitelist() function.
 - for local testing you can use "127.0.0.1"
2) Run the above test again and you should no longer be blocked

