package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
)

type UploadRequest struct {
	VideoURL      string   `json:"video_url" binding:"required"`
	Title         string   `json:"title" binding:"required"`
	Description   string   `json:"description" binding:"required"`
	Tags          []string `json:"tags"`
	PrivacyStatus string   `json:"privacy_status" binding:"required"`
}

type ProgressReader struct {
	Reader   io.Reader
	Total    int64
	Uploaded int64
	StartAt  time.Time
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	pr.Uploaded += int64(n)
	pr.printProgress()
	return n, err
}

func (pr *ProgressReader) Start() {
	pr.StartAt = time.Now()
	fmt.Println("Starting upload...")
}

func (pr *ProgressReader) Stop() {
	fmt.Println("\nUpload completed.")
}

func (pr *ProgressReader) printProgress() {
	percent := float64(pr.Uploaded) / float64(pr.Total) * 100
	fmt.Printf("\rProgress: %.2f%% (%d/%d bytes)", percent, pr.Uploaded, pr.Total)
}

func main() {
	r := gin.Default()

	// CORS Middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{os.Getenv("URL_FRONTEND")},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.POST("/upload", uploadHandler)
	r.GET("/oauth/callback", oauthCallbackHandler)

	r.Run(":8080") // Run the server
}

func uploadHandler(c *gin.Context) {
	var req UploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Load OAuth2 configuration
	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("error reading client_secret.json file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		log.Fatalf("error configuring OAuth2: %v", err)
	}

	tokFile := "token.json"
	if _, err := os.Stat(tokFile); os.IsNotExist(err) {
		// If the token.json file does not exist, return the authorization link
		authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":    "OAuth token not found.",
			"auth_url": authURL,
		})
		return
	}

	// Use the existing token to continue the process
	client := getClient(ctx, config)
	service, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create YouTube service"})
		return
	}

	// Download and upload the video
	videoPath := "downloaded_video.mp4"
	if err := downloadVideo(req.VideoURL, videoPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to download video: %v", err)})
		return
	}
	defer os.Remove(videoPath)

	if err := uploadVideoWithProgress(service, videoPath, req.Title, req.Description, req.Tags, req.PrivacyStatus); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to upload video: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Video uploaded successfully!"})
}

func oauthCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		return
	}

	ctx := context.Background()
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

	tok, err := config.Exchange(ctx, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
		return
	}

	saveToken("token.json", tok)
	c.JSON(http.StatusOK, gin.H{"message": "Authorization successful"})
}

func downloadVideo(videoURL, outputPath string) error {
	resp, err := http.Get(videoURL)
	if err != nil {
		return fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error downloading: status %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	fmt.Println("Download completed:", outputPath)
	return nil
}

func uploadVideoWithProgress(service *youtube.Service, filePath, title, description string, tags []string, privacyStatus string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %v", err)
	}
	fileSize := fileInfo.Size()

	video := &youtube.Video{
		Snippet: &youtube.VideoSnippet{
			Title:       title,
			Description: description,
			Tags:        tags,
		},
		Status: &youtube.VideoStatus{
			PrivacyStatus: privacyStatus,
		},
	}

	progressReader := &ProgressReader{
		Reader: file,
		Total:  fileSize,
	}
	progressReader.Start()

	call := service.Videos.Insert([]string{"snippet", "status"}, video)
	call = call.Media(progressReader)

	_, err = call.Do()
	progressReader.Stop()
	if err != nil {
		return fmt.Errorf("error uploading video: %v", err)
	}

	return nil
}

func getClient(ctx context.Context, config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = nil
	}
	return config.Client(ctx, tok)
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving token to %s\n", path)
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("error saving token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
