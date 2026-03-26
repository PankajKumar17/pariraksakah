package dnamw

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var trustRegistryURL = os.Getenv("DNA_TRUST_REGISTRY_URL")

// VerifyDNA is the middleware to check Trust Registry
func VerifyDNA(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		callerDNA := c.GetHeader("X-Caller-DNA-ID")
		if callerDNA == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing DNA Identity"})
			return
		}

		// Fast path cache can be added here
		resp, err := http.Get(trustRegistryURL + "/trust/verify/" + callerDNA + "/" + serviceName)
		if err != nil || resp.StatusCode != http.StatusOK {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "DNA Trust Score Verification Failed"})
			return
		}

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		
		c.Writer.Header().Set("X-Component-DNA", serviceName+"-DNA-Hash")
		c.Next()
	}
}
