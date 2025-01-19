package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
)

func main() {
	ctx := context.Background()

	// Load the client_secret.json file
	b, err := os.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("error reading client_secret.json file: %v", err)
	}

	// Configure OAuth2
	config, err := google.ConfigFromJSON(b, youtube.YoutubeScope)
	if err != nil {
		log.Fatalf("error configuring OAuth2: %v", err)
	}

	// Get the authenticated OAuth2 client
	client := getClient(ctx, config)

	// Create a YouTube service
	service, err := youtube.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("error creating YouTube service: %v", err)
	}

	// Get video URL from user input
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the video URL: ")
	videoURL, _ := reader.ReadString('\n')
	videoURL = strings.TrimSpace(videoURL)
	videoPath := "downloaded_video.mp4"

	// Get video title from user input
	fmt.Print("Enter the video title: ")
	title, _ := reader.ReadString('\n')
	title = strings.TrimSpace(title)

	// Get video description from user input
	fmt.Print("Enter the video description: ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)

	// Get video tags from user input
	fmt.Print("Enter the video tags (comma separated): ")
	tagsInput, _ := reader.ReadString('\n')
	tags := strings.Split(strings.TrimSpace(tagsInput), ",")

	// Get privacy status from user input
	prompt := promptui.Select{
		Label: "Select Privacy Status",
		Items: []string{"public", "private", "unlisted"},
	}
	_, privacyStatus, err := prompt.Run()
	if err != nil {
		log.Fatalf("error selecting privacy status: %v", err)
	}

	// Download the video from the URL
	err = downloadVideo(videoURL, videoPath)
	if err != nil {
		log.Fatalf("error downloading video: %v", err)
	}
	defer os.Remove(videoPath) // Delete the video after upload

	// Upload the video to YouTube with progress tracking
	err = uploadVideoWithProgress(service, videoPath, title, description, tags, privacyStatus)
	if err != nil {
		log.Fatalf("error uploading video: %v", err)
	}

	fmt.Println("\nVideo uploaded successfully!")
}

// downloadVideo downloads a video from a URL
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

// uploadVideoWithProgress uploads a video to YouTube and displays the progress
func uploadVideoWithProgress(service *youtube.Service, filePath, title, description string, tags []string, privacyStatus string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Get the file size for progress tracking
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %v", err)
	}
	fileSize := fileInfo.Size()

	// Create a metadata object for the video
	video := &youtube.Video{
		Snippet: &youtube.VideoSnippet{
			Title:       title,
			Description: description,
			Tags:        tags,
		},
		Status: &youtube.VideoStatus{
			PrivacyStatus: privacyStatus, // Choose between "public", "private", "unlisted"
		},
	}

	// Manual progress tracking
	progressReader := &ProgressReader{
		Reader: file,
		Total:  fileSize,
	}
	progressReader.Start()

	// Upload the video
	call := service.Videos.Insert([]string{"snippet", "status"}, video)
	call = call.Media(progressReader)

	_, err = call.Do()
	progressReader.Stop()
	if err != nil {
		return fmt.Errorf("error uploading video: %v", err)
	}

	return nil
}

// ProgressReader allows tracking progress during reading
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

// getClient handles the OAuth2 process
func getClient(ctx context.Context, config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(ctx, tok)
}

// getTokenFromWeb sets up a local server to capture the authorization code
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	// Set up a local server
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("error setting up local server: %v", err)
	}
	defer listener.Close()

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Visit this link in your browser to authorize access:\n%v\n", authURL)

	codeCh := make(chan string)

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			if code != "" {
				fmt.Fprintf(w, "Authorization received. You can close this page.")
				codeCh <- code
			} else {
				http.Error(w, "missing authorization code", http.StatusBadRequest)
			}
		})
		http.Serve(listener, nil)
	}()

	code := <-codeCh
	tok, err := config.Exchange(context.Background(), code)
	if err != nil {
		log.Fatalf("error exchanging authorization code: %v", err)
	}
	return tok
}

// tokenFromFile reads an OAuth2 token from a file
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

// saveToken saves an OAuth2 token to a file
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving token to %s\n", path)
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("error saving token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
