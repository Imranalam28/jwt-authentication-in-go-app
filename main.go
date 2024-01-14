package main

// Import the required packages
import (
	"fmt"
	"time"
	"net/http"
	"strconv"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)
// Add a new global variable for the secret key
var secretKey = []byte("your-secret-key")

type Todo struct {
	Text string
	Done bool
}

var todos []Todo
var loggedInUser string


func main() {
	router := gin.Default()

	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Todos":    todos,
			"LoggedIn": loggedInUser != "",
			"Username": loggedInUser,
			"Role":     getRole(loggedInUser),
		})
	})

	router.POST("/add", authenticateMiddleware, func(c *gin.Context) {
		text := c.PostForm("todo")
		todo := Todo{Text: text, Done: false}
		todos = append(todos, todo)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.POST("/toggle", authenticateMiddleware, func(c *gin.Context) {
		index := c.PostForm("index")
		toggleIndex(index)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.GET("/logout", func(c *gin.Context) {
		loggedInUser = ""
		c.SetCookie("token", "", -1, "/", "localhost", false, true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		// Dummy credential check
		if (username == "employee" && password == "password") || (username == "senior" && password == "password") {
			tokenString, err := createToken(username)
			if err != nil {
				c.String(http.StatusInternalServerError, "Error creating token")
				return
			}

			loggedInUser = username
			fmt.Printf("Token created: %s\n", tokenString)
			c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)
			c.Redirect(http.StatusSeeOther, "/")
		} else {
			c.String(http.StatusUnauthorized, "Invalid credentials")
		}
	})


	router.Run(":8080")
}

func toggleIndex(index string) {
	i, _ := strconv.Atoi(index)
	if i >= 0 && i < len(todos) {
		todos[i].Done = !todos[i].Done
	}
}

// Function to create JWT tokens with claims
func createToken(username string) (string, error) {
    // Create a new JWT token with claims
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,                    // Subject (user identifier)
		"iss": "todo-app",                  // Issuer
		"aud": getRole(username),           // Audience (user role)
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                 // Issued at
	})

	tokenString, err := claims.SignedString(secretKey)
    if err != nil {
        return "", err
    }

  // Print information about the created token
	fmt.Printf("Token claims added: %+v\n", claims)
	return tokenString, nil
}

func getRole(username string) string {
	if username == "senior" {
		return "senior"
	}
	return "employee"
}

// Function to verify JWT tokens
func authenticateMiddleware(c *gin.Context) {
	// Retrieve the token from the cookie
	tokenString, err := c.Cookie("token")
	if err != nil {
		fmt.Println("Token missing in cookie")
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// Verify the token
	token, err := verifyToken(tokenString)
	if err != nil {
		fmt.Printf("Token verification failed: %v\\n", err)
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// Print information about the verified token
	fmt.Printf("Token verified successfully. Claims: %+v\\n", token.Claims)

	// Continue with the next middleware or route handler
	c.Next()
}

// Function to verify JWT tokens
func verifyToken(tokenString string) (*jwt.Token, error) {
	// Parse the token with the secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	// Check for verification errors
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Return the verified token
	return token, nil
}




