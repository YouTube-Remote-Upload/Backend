package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var firebaseApp *firestore.Client

type UploadRequest struct {
	VideoURL      string   `json:"video_url" binding:"required"`
	Title         string   `json:"title" binding:"required"`
	Description   string   `json:"description" binding:"required"`
	Tags          []string `json:"tags"`
	PrivacyStatus string   `json:"privacy_status" binding:"required"`
}

func main() {
	initializeFirebase()

	r := gin.Default()

	// Middleware CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{os.Getenv("CORS_ALLOW_ORIGIN")},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/login", loginHandler)
	r.GET("/oauth/callback", oauthCallbackHandler)
	r.GET("/refresh", refreshJWTHandler)

	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.POST("/upload", uploadHandler)
	}

	r.Run(":8080")
}

func initializeFirebase() {
	ctx := context.Background()
	client, err := firestore.NewClient(ctx, "upload-123ea", option.WithCredentialsFile("serviceAccountKey.json"))
	if err != nil {
		log.Fatalf("Failed to initialize Firebase: %v", err)
	}
	firebaseApp = client
	log.Println("Firebase initialized successfully!")
}

func loginHandler(c *gin.Context) {
	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("Error reading client_secret.json file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		log.Fatalf("Error configuring OAuth2: %v", err)
	}

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, authURL)
}

func refreshJWTHandler(c *gin.Context) {
	userID := c.GetString("user_id") // Obtained via middleware or JWT parsing

	// Retrieve the OAuth token from Firestore
	token, err := getTokenFromFirestore(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Check if the refresh_token is still valid and renew if necessary
	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read client_secret.json"})
		return
	}

	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse OAuth config"})
		return
	}

	tokenSource := config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh access token"})
		return
	}

	// Update Firestore with the new token
	if err := saveTokenToFirestore(userID, newToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update token in Firestore"})
		return
	}

	// Generate a new JWT for the client
	newJWT, err := generateJWT(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new JWT"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newJWT})
}

func oauthCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		return
	}

	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read client_secret.json"})
		return
	}

	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse OAuth config"})
		return
	}

	ctx := context.Background()
	tok, err := config.Exchange(ctx, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
		return
	}

	client := config.Client(ctx, tok)
	service, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create YouTube service"})
		return
	}

	call := service.Channels.List([]string{"snippet"}).Mine(true)
	response, err := call.Do()
	if err != nil || len(response.Items) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	userID := response.Items[0].Id
	if err := saveTokenToFirestore(userID, tok); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save token"})
		return
	}

	jwtToken, err := generateJWT(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	redirectURL := fmt.Sprintf("http://localhost:5173/upload?token=%s", jwtToken)
	c.Redirect(http.StatusFound, redirectURL)
}

func getAuthenticatedClient(userID string) (*http.Client, error) {
	token, err := getTokenFromFirestore(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token: %v", err)
	}

	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read client_secret.json: %v", err)
	}

	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OAuth config: %v", err)
	}

	// Create a TokenSource that automatically handles renewal
	tokenSource := config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}

	// If the token is refreshed, update Firestore
	if newToken.AccessToken != token.AccessToken {
		if err := saveTokenToFirestore(userID, newToken); err != nil {
			return nil, fmt.Errorf("failed to update token in Firestore: %v", err)
		}
	}

	// Return an authenticated client
	return oauth2.NewClient(context.Background(), tokenSource), nil
}

func uploadHandler(c *gin.Context) {
	var req UploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input", "details": err.Error()})
		return
	}

	userID := c.GetString("user_id")
	client, err := getAuthenticatedClient(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated", "details": err.Error()})
		return
	}

	service, err := youtube.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create YouTube service"})
		return
	}

	// Continue with the upload as before
	videoPath := generateTempFileName()
	if err := downloadVideo(req.VideoURL, videoPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download video", "details": err.Error()})
		return
	}
	defer os.Remove(videoPath)

	file, err := os.Open(videoPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open video file", "details": err.Error()})
		return
	}
	defer file.Close()

	video := &youtube.Video{
		Snippet: &youtube.VideoSnippet{
			Title:       req.Title,
			Description: req.Description,
			Tags:        req.Tags,
		},
		Status: &youtube.VideoStatus{
			PrivacyStatus: req.PrivacyStatus,
		},
	}

	call := service.Videos.Insert([]string{"snippet", "status"}, video).Media(file)
	_, err = call.Do()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload video", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Video uploaded successfully!"})
}

func generateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func generateTempFileName() string {
	return fmt.Sprintf("tmp_%d.mp4", time.Now().UnixNano())
}

func downloadVideo(videoURL, outputPath string) error {
	resp, err := http.Get(videoURL)
	if err != nil {
		return fmt.Errorf("failed to download video: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download video: HTTP status %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save video: %v", err)
	}

	return nil
}

func saveTokenToFirestore(userID string, token *oauth2.Token) error {
	_, err := firebaseApp.Collection("tokens").Doc(userID).Set(context.Background(), map[string]interface{}{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"expiry":        token.Expiry,
	})
	return err
}

func getTokenFromFirestore(userID string) (*oauth2.Token, error) {
	doc, err := firebaseApp.Collection("tokens").Doc(userID).Get(context.Background())
	if err != nil {
		return nil, err
	}

	data := doc.Data()
	return &oauth2.Token{
		AccessToken:  data["access_token"].(string),
		RefreshToken: data["refresh_token"].(string),
		Expiry:       data["expiry"].(time.Time),
	}, nil
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing or invalid"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Check if the JWT is expired
		exp := int64(claims["exp"].(float64))
		if time.Now().Unix() > exp {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "JWT expired"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Next()
	}
}
