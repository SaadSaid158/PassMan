package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// Configuration constants
const (
	appName           = "passman"
	appVersion        = "1.2.0"
	configFileName    = "config.json"
	storeFileName     = "store.json"
	lockFileName      = "lockout.json"
	saltLength        = 32          // Increased from 16 for better security
	keyLength         = 32
	scryptN           = 32768
	scryptR           = 8
	scryptP           = 1
	maxAttempts       = 5
	hmacKeyLength     = 32
	backoffFactor     = 2 // Exponential backoff factor
	minPassLength     = 12
	clipboardTimeout  = 30 // Seconds before clipboard is cleared
	maxBackupFiles    = 5  // Maximum number of backup files to keep
	maxInputLength    = 256 // Maximum input length for non-password fields
)

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// Password generation character sets
const (
	charsetLower     = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigits    = "0123456789"
	charsetSpecial   = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
	defaultPassLen   = 20
)

// Valid characters for password generation and validation
var validPasswordChars = charsetLower + charsetUpper + charsetDigits + charsetSpecial

// Command line flags
var (
	secureFlag    bool
	helpFlag      bool
	versionFlag   bool
	searchTerm    string
	rotateService string
	rotateLength  int
	clipTimeout   int
)

// PlatformPaths holds file paths specific to the current platform
type PlatformPaths struct {
	ConfigDir  string // Directory for configuration files
	ConfigFile string // Main configuration file
	StoreFile  string // Credential store file
	LogFile    string // Log file
	LockFile   string // Lockout state file
}

// LockoutState holds information about failed login attempts
type LockoutState struct {
	FailedAttempts int       `json:"failed_attempts"`
	LastAttempt    time.Time `json:"last_attempt"`
	LockoutUntil   time.Time `json:"lockout_until"`
	HMAC           string    `json:"hmac"`
}

// Config holds application configuration
type Config struct {
	Version        string   `json:"version"`
	FirstRun       bool     `json:"first_run"`
	AllowedUsers   []string `json:"allowed_users"`
	StoragePath    string   `json:"storage_path"`
	LoggingEnabled bool     `json:"logging_enabled"`
	Platform       string   `json:"platform"`
	EncryptedData  string   `json:"encrypted_data,omitempty"`
	Salt           string   `json:"salt,omitempty"`
	HMAC           string   `json:"hmac,omitempty"`
}

// Store struct to hold encrypted credentials and master password hash
type Store struct {
	MasterHash string                `json:"master_hash"`
	Salt       string                `json:"salt"`
	Creds      map[string]Credential `json:"creds"`
	HMAC       string                `json:"hmac"`
	Version    string                `json:"version"`
	LastUpdate time.Time             `json:"last_update"`
}

// Credential holds encrypted username and password
type Credential struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Notes    string    `json:"notes,omitempty"`
}

// Global variables
var (
	paths        PlatformPaths
	config       Config
	colorized    bool
	isTerminal   bool
	lockedMemory [][]byte // Slices of memory that have been locked
)

// Initialize application
func init() {
	// Parse command line flags
	flag.BoolVar(&secureFlag, "secure", false, "Suppress sensitive output (for scripts)")
	flag.BoolVar(&helpFlag, "help", false, "Show help information")
	flag.BoolVar(&versionFlag, "version", false, "Show version information")
	flag.StringVar(&searchTerm, "search", "", "Search for credentials by service name")
	flag.StringVar(&rotateService, "rotate", "", "Rotate password for specified service")
	flag.IntVar(&rotateLength, "length", defaultPassLen, "Length for generated passwords")
	flag.IntVar(&clipTimeout, "clip-timeout", clipboardTimeout, "Seconds before clipboard is cleared")
	
	// Check if output is a terminal
	isTerminal = term.IsTerminal(int(os.Stdout.Fd()))
	
	// Enable colors if terminal supports it
	termEnv := os.Getenv("TERM")
	colorized = isTerminal && termEnv != "dumb" && termEnv != ""
	
	// Detect platform and set paths
	platform := detectPlatform()
	paths = getPlatformPaths(platform)
	
	// Initialize locked memory slice
	lockedMemory = make([][]byte, 0)
}

// detectPlatform determines the current operating system platform
func detectPlatform() string {
	// Check for Raspberry Pi
	if _, err := os.Stat("/proc/device-tree/model"); err == nil {
		data, err := os.ReadFile("/proc/device-tree/model")
		if err == nil {
			// Fix: Handle null byte in Raspberry Pi model string
			modelStr := strings.TrimRight(string(data), "\x00")
			if strings.Contains(modelStr, "Raspberry Pi") {
				return "raspberrypi"
			}
		}
	}
	
	// Check for Debian/Ubuntu
	if _, err := os.Stat("/etc/os-release"); err == nil {
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			osReleaseStr := string(data)
			if strings.Contains(osReleaseStr, "ID=debian") {
				return "debian"
			}
			if strings.Contains(osReleaseStr, "ID=ubuntu") {
				return "ubuntu"
			}
			if strings.Contains(osReleaseStr, "ID=raspbian") {
				return "raspberrypi"
			}
		}
	}
	
	// Default to Linux
	return "linux"
}

// getPlatformPaths returns appropriate file paths based on platform
func getPlatformPaths(platform string) PlatformPaths {
	var p PlatformPaths
	
	// Common paths for Linux-based systems
	if platform == "raspberrypi" || platform == "debian" || platform == "ubuntu" || platform == "linux" {
		// For root user, use system directories
		if isRoot() {
			p.ConfigDir = "/etc/passman"
			p.ConfigFile = "/etc/passman/config.json"
			p.StoreFile = "/etc/passman/store.json"
			p.LogFile = "/var/log/passman.log"
			p.LockFile = "/etc/passman/lockout.json"
		} else {
			// For non-root users, use home directory
			homeDir, err := os.UserHomeDir()
			if err != nil {
				homeDir = "."
			}
			configDir := filepath.Join(homeDir, ".config", "passman")
			p.ConfigDir = configDir
			p.ConfigFile = filepath.Join(configDir, "config.json")
			p.StoreFile = filepath.Join(configDir, "store.json")
			p.LogFile = filepath.Join(configDir, "passman.log")
			p.LockFile = filepath.Join(configDir, "lockout.json")
		}
	}
	
	return p
}

// clearScreen clears the terminal screen in a platform-appropriate way
func clearScreen() {
	if !isTerminal || secureFlag {
		return
	}
	
	// Use the clear command which is available on most Linux systems
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// colorPrint prints text with specified color if terminal supports it
func colorPrint(color, format string, args ...interface{}) {
	if colorized && !secureFlag {
		fmt.Printf(color+format+colorReset, args...)
	} else if !secureFlag {
		fmt.Printf(format, args...)
	}
}

// printSuccess prints success messages in green
func printSuccess(format string, args ...interface{}) {
	if !secureFlag {
		colorPrint(colorGreen, "[+] "+format+"\n", args...)
	}
}

// printInfo prints informational messages in blue
func printInfo(format string, args ...interface{}) {
	if !secureFlag {
		colorPrint(colorBlue, "[*] "+format+"\n", args...)
	}
}

// printWarning prints warning messages in yellow
func printWarning(format string, args ...interface{}) {
	if !secureFlag {
		colorPrint(colorYellow, "[!] "+format+"\n", args...)
	}
}

// printError prints error messages in red
func printError(format string, args ...interface{}) {
	if !secureFlag {
		colorPrint(colorRed, "[-] "+format+"\n", args...)
	}
}

// showProgress displays a progress indicator for long operations
func showProgress(operation string, durationSec int) {
	if secureFlag || !isTerminal {
		return
	}
	
	// Create a channel to signal completion
	done := make(chan bool)
	
	// Start progress indicator in a goroutine
	go func() {
		spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-done:
				fmt.Print("\r")
				fmt.Print(strings.Repeat(" ", len(operation)+10))
				fmt.Print("\r")
				return
			default:
				fmt.Printf("\r%s %s", spinChars[i], operation)
				i = (i + 1) % len(spinChars)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	
	// Wait for the specified duration
	time.Sleep(time.Duration(durationSec) * time.Second)
	
	// Signal completion
	done <- true
}

// readInput reads user input with optional hidden input (for passwords)
func readInput(prompt string, hidden bool) (string, error) {
	if !secureFlag {
		fmt.Print(prompt)
	}
	
	var input []byte
	var err error

	if hidden {
		input, err = term.ReadPassword(int(syscall.Stdin)) // Uses x/term for secure input
		if !secureFlag {
			fmt.Println()
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		inputStr, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading input: %w", err)
		}
		
		// Trim newline and limit input length
		inputStr = strings.TrimSpace(inputStr)
		if len(inputStr) > maxInputLength {
			inputStr = inputStr[:maxInputLength]
		}
		
		return inputStr, nil
	}

	if err != nil {
		return "", fmt.Errorf("error reading input: %w", err)
	}
	
	// Trim and limit password length
	password := strings.TrimSpace(string(input))
	if len(password) > maxInputLength {
		password = password[:maxInputLength]
	}
	
	return password, nil
}

// isRoot checks if the program is run as root (UID 0)
func isRoot() bool {
	u, err := user.Current()
	if err != nil || u.Uid != "0" {
		return false
	}
	return true
}

// lockMemory locks a byte slice in memory to prevent it from being swapped to disk
func lockMemory(data []byte) ([]byte, error) {
	// Create a copy of the data to ensure it's properly aligned
	lockedData := make([]byte, len(data))
	copy(lockedData, data)
	
	// Lock the memory
	if runtime.GOOS == "linux" {
		// Use mlock on Linux
		if err := syscall.Mlock(lockedData); err != nil {
			// Don't fail if mlock fails, just warn
			printWarning("Failed to lock memory: %v", err)
			return data, nil
		}
		
		// Add to the list of locked memory for later unlocking
		lockedMemory = append(lockedMemory, lockedData)
	}
	
	return lockedData, nil
}

// unlockMemory unlocks previously locked memory
func unlockMemory(data []byte) error {
	if runtime.GOOS == "linux" {
		// Use munlock on Linux
		if err := syscall.Munlock(data); err != nil {
			return fmt.Errorf("failed to unlock memory: %w", err)
		}
	}
	
	return nil
}

// unlockAllMemory unlocks all previously locked memory
func unlockAllMemory() {
	for _, data := range lockedMemory {
		if err := unlockMemory(data); err != nil {
			printWarning("Failed to unlock memory: %v", err)
		}
		
		// Zero out the data
		for i := range data {
			data[i] = 0
		}
	}
	
	// Clear the list of locked memory
	lockedMemory = make([][]byte, 0)
}

// secureZeroMemory zeroes out a byte slice to remove sensitive data
// Uses a volatile pointer to prevent compiler optimization
func secureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}
	
	// Get a pointer to the first byte
	ptr := unsafe.Pointer(&data[0])
	
	// Zero out the memory
	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = 0
	}
	
	// Force garbage collection to clean up
	runtime.GC()
}

// generateKey derives a key from the master password and salt using scrypt
func generateKey(password, salt []byte) ([]byte, error) {
	// Show progress indicator for key derivation
	if !secureFlag && isTerminal {
		go showProgress("Deriving key", 1)
	}
	
	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLength)
	if err != nil {
		return nil, fmt.Errorf("scrypt key generation failed: %w", err)
	}
	
	// Lock the key in memory
	lockedKey, err := lockMemory(key)
	if err != nil {
		printWarning("Failed to lock key in memory: %v", err)
		// Continue with the original key if locking fails
		return key, nil
	}
	
	return lockedKey, nil
}

// encrypt encrypts the data with AES-GCM
func encrypt(data, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation failed: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM cipher creation failed: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the data with AES-GCM
func decrypt(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil || len(data) < 12 {
		return "", errors.New("invalid base64 or insufficient data")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM cipher creation failed: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	
	nonce, encryptedData := data[:nonceSize], data[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	// Lock the plaintext in memory
	lockedPlaintext, err := lockMemory(plaintext)
	if err != nil {
		printWarning("Failed to lock plaintext in memory: %v", err)
		// Continue with the original plaintext if locking fails
		return string(plaintext), nil
	}
	
	return string(lockedPlaintext), nil
}

// computeHMAC computes the HMAC of the given data using the given key
func computeHMAC(data []byte, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// hmacEqual checks if two HMAC values are equal in constant time
func hmacEqual(hmac1, hmac2 string) bool {
	h1, err1 := base64.StdEncoding.DecodeString(hmac1)
	h2, err2 := base64.StdEncoding.DecodeString(hmac2)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return hmac.Equal(h1, h2)
}

// validatePasswordStrength checks if a password meets strength requirements
func validatePasswordStrength(password string) error {
	if len(password) < minPassLength {
		return fmt.Errorf("password must be at least %d characters long", minPassLength)
	}
	
	// Check for character variety
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	var missing []string
	if !hasUpper {
		missing = append(missing, "uppercase letters")
	}
	if !hasLower {
		missing = append(missing, "lowercase letters")
	}
	if !hasDigit {
		missing = append(missing, "digits")
	}
	if !hasSpecial {
		missing = append(missing, "special characters")
	}
	
	if len(missing) > 0 {
		return fmt.Errorf("password must contain: %s", strings.Join(missing, ", "))
	}
	
	// Check for common patterns
	if strings.Contains(strings.ToLower(password), "password") {
		return errors.New("password contains common word 'password'")
	}
	
	if strings.Contains(strings.ToLower(password), "123456") {
		return errors.New("password contains common sequence '123456'")
	}
	
	return nil
}

// generateRandomPassword generates a cryptographically secure random password
func generateRandomPassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New("password length must be at least 8 characters")
	}
	
	// Ensure we have at least one of each character type
	password := make([]byte, length)
	
	// Fill with random characters
	if _, err := io.ReadFull(rand.Reader, password); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	// Convert random bytes to valid characters
	allChars := charsetLower + charsetUpper + charsetDigits + charsetSpecial
	for i := range password {
		password[i] = allChars[int(password[i])%len(allChars)]
	}
	
	// Ensure we have at least one of each character type
	password[0] = charsetLower[int(password[0])%len(charsetLower)]
	password[1] = charsetUpper[int(password[1])%len(charsetUpper)]
	password[2] = charsetDigits[int(password[2])%len(charsetDigits)]
	password[3] = charsetSpecial[int(password[3])%len(charsetSpecial)]
	
	// Shuffle the password
	for i := len(password) - 1; i > 0; i-- {
		j := int(password[i]) % (i + 1)
		password[i], password[j] = password[j], password[i]
	}
	
	return string(password), nil
}

// copyToClipboard copies text to the system clipboard
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	
	// On Linux, try xclip first, then xsel
	cmd = exec.Command("xclip", "-selection", "clipboard")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		// Try xsel as fallback
		cmd = exec.Command("xsel", "--clipboard", "--input")
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("clipboard tools not available: %w", err)
		}
	}
	
	if err := cmd.Start(); err != nil {
		return err
	}
	
	if _, err := stdin.Write([]byte(text)); err != nil {
		return err
	}
	
	if err := stdin.Close(); err != nil {
		return err
	}
	
	return cmd.Wait()
}

// clearClipboard clears the system clipboard
func clearClipboard() error {
	return copyToClipboard("")
}

// copyToClipboardWithTimeout copies text to clipboard and clears it after timeout
func copyToClipboardWithTimeout(text string, timeoutSec int) {
	if err := copyToClipboard(text); err != nil {
		printError("Failed to copy to clipboard: %v", err)
		printInfo("You may need to install xclip or xsel: sudo apt-get install xclip")
		return
	}
	
	printSuccess("Copied to clipboard, will clear in %d seconds", timeoutSec)
	
	// Start countdown in a goroutine
	go func() {
		for i := timeoutSec; i > 0; i-- {
			if i%5 == 0 || i <= 5 {
				if !secureFlag {
					fmt.Printf("\rClipboard will clear in %d seconds...", i)
				}
			}
			time.Sleep(1 * time.Second)
		}
		
		if err := clearClipboard(); err != nil {
			printError("\rFailed to clear clipboard: %v", err)
		} else {
			if !secureFlag {
				fmt.Print("\rClipboard cleared successfully.           \n")
			}
		}
	}()
}

// ensureDirectories creates necessary directories with proper permissions
func ensureDirectories() error {
	// Create config directory if it doesn't exist
	if _, err := os.Stat(paths.ConfigDir); os.IsNotExist(err) {
		// Create with more permissive permissions initially
		if err := os.MkdirAll(paths.ConfigDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}
	
	return nil
}

// ensurePassmanGroup creates the passman group if it doesn't exist
func ensurePassmanGroup() error {
	// Check if group exists
	_, err := exec.Command("getent", "group", appName).Output()
	if err != nil {
		// Create group
		cmd := exec.Command("groupadd", appName)
		if err := cmd.Run(); err != nil {
			// If groupadd fails, try to continue anyway
			printWarning("Failed to create %s group: %v", appName, err)
			printWarning("Some features may not work correctly")
			return nil
		}
		printSuccess("Created %s group", appName)
	}
	
	return nil
}

// setFilePermissions sets proper permissions on files
func setFilePermissions() error {
	// Set store file permissions if it exists
	if _, err := os.Stat(paths.StoreFile); err == nil {
		if err := os.Chmod(paths.StoreFile, 0640); err != nil {
			printWarning("Failed to set store permissions: %v", err)
		}
	}
	
	// Set config file permissions if it exists
	if _, err := os.Stat(paths.ConfigFile); err == nil {
		if err := os.Chmod(paths.ConfigFile, 0640); err != nil {
			printWarning("Failed to set config permissions: %v", err)
		}
	}
	
	// Set lockout file permissions if it exists
	if _, err := os.Stat(paths.LockFile); err == nil {
		if err := os.Chmod(paths.LockFile, 0640); err != nil {
			printWarning("Failed to set lockout file permissions: %v", err)
		}
	}
	
	// Set group ownership if running as root
	if isRoot() {
		// Check if group exists before trying to set ownership
		if _, err := exec.Command("getent", "group", appName).Output(); err == nil {
			// Set group ownership on store file if it exists
			if _, err := os.Stat(paths.StoreFile); err == nil {
				cmd := exec.Command("chgrp", appName, paths.StoreFile)
				if err := cmd.Run(); err != nil {
					printWarning("Failed to set group ownership on store: %v", err)
				}
			}
			
			// Set group ownership on config file if it exists
			if _, err := os.Stat(paths.ConfigFile); err == nil {
				cmd := exec.Command("chgrp", appName, paths.ConfigFile)
				if err := cmd.Run(); err != nil {
					printWarning("Failed to set group ownership on config: %v", err)
				}
			}
			
			// Set group ownership on lockout file if it exists
			if _, err := os.Stat(paths.LockFile); err == nil {
				cmd := exec.Command("chgrp", appName, paths.LockFile)
				if err := cmd.Run(); err != nil {
					printWarning("Failed to set group ownership on lockout file: %v", err)
				}
			}
			
			// Set group ownership on config directory
			cmd := exec.Command("chgrp", appName, paths.ConfigDir)
			if err := cmd.Run(); err != nil {
				printWarning("Failed to set group ownership on config directory: %v", err)
			}
		}
	}
	
	return nil
}

// cleanupBackups removes old backup files, keeping only the most recent ones
func cleanupBackups() {
	// Get all backup files
	backupPattern := paths.StoreFile + ".backup.*"
	matches, err := filepath.Glob(backupPattern)
	if err != nil || len(matches) <= maxBackupFiles {
		return
	}
	
	// Sort by modification time (newest first)
	sort.Slice(matches, func(i, j int) bool {
		iInfo, err := os.Stat(matches[i])
		if err != nil {
			return false
		}
		jInfo, err := os.Stat(matches[j])
		if err != nil {
			return true
		}
		return iInfo.ModTime().After(jInfo.ModTime())
	})
	
	// Remove older backups
	for i := maxBackupFiles; i < len(matches); i++ {
		os.Remove(matches[i])
	}
}

// loadConfig loads the application configuration
func loadConfig() error {
	// Check if config file exists
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		// Create default config
		config = Config{
			Version:        appVersion,
			FirstRun:       true,
			AllowedUsers:   []string{},
			StoragePath:    paths.StoreFile,
			LoggingEnabled: true,
			Platform:       detectPlatform(),
		}
		return saveConfig()
	}
	
	// Read config file
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	
	return nil
}

// saveConfig saves the application configuration
func saveConfig() error {
	// Ensure the config directory exists
	if err := ensureDirectories(); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Create the file with restrictive permissions
	file, err := os.OpenFile(paths.ConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()
	
	// Write the data
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// encryptConfig encrypts sensitive configuration data with the master password
func encryptConfig(masterKey []byte) error {
	// Create a copy of the config without sensitive fields
	configCopy := config
	configCopy.EncryptedData = ""
	configCopy.Salt = ""
	configCopy.HMAC = ""
	
	// Marshal the sensitive data
	sensitiveData, err := json.Marshal(configCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal sensitive config data: %w", err)
	}
	
	// Generate a new salt for config encryption
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Encrypt the sensitive data
	encryptedData, err := encrypt(sensitiveData, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt config data: %w", err)
	}
	
	// Update the config
	config.EncryptedData = encryptedData
	config.Salt = base64.StdEncoding.EncodeToString(salt)
	
	// Compute HMAC for the encrypted data
	hmacData := []byte(config.EncryptedData + config.Salt)
	config.HMAC = computeHMAC(hmacData, masterKey)
	
	return saveConfig()
}

// decryptConfig decrypts sensitive configuration data with the master password
func decryptConfig(masterKey []byte) error {
	// Check if config is encrypted
	if config.EncryptedData == "" || config.Salt == "" || config.HMAC == "" {
		return nil // Not encrypted, nothing to do
	}
	
	// Verify HMAC
	hmacData := []byte(config.EncryptedData + config.Salt)
	hmac := computeHMAC(hmacData, masterKey)
	if !hmacEqual(hmac, config.HMAC) {
		return errors.New("config integrity check failed: HMAC mismatch")
	}
	
	// Decrypt the data
	decryptedData, err := decrypt(config.EncryptedData, masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt config data: %w", err)
	}
	
	// Parse the decrypted data
	var decryptedConfig Config
	if err := json.Unmarshal([]byte(decryptedData), &decryptedConfig); err != nil {
		return fmt.Errorf("failed to parse decrypted config data: %w", err)
	}
	
	// Update non-sensitive fields from decrypted data
	config.AllowedUsers = decryptedConfig.AllowedUsers
	config.LoggingEnabled = decryptedConfig.LoggingEnabled
	
	// Zero out decrypted data
	secureZeroMemory([]byte(decryptedData))
	
	return nil
}

// loadLockoutState loads the lockout state from the lockout file
func loadLockoutState() (LockoutState, error) {
	var state LockoutState
	
	// Check if lockout file exists
	if _, err := os.Stat(paths.LockFile); os.IsNotExist(err) {
		// Return empty state
		return state, nil
	}
	
	// Read lockout file
	data, err := os.ReadFile(paths.LockFile)
	if err != nil {
		return state, fmt.Errorf("failed to read lockout file: %w", err)
	}
	
	// Handle empty file
	if len(data) == 0 {
		return state, nil
	}
	
	// Parse lockout state
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("failed to parse lockout state: %w", err)
	}
	
	return state, nil
}

// saveLockoutState saves the lockout state to the lockout file
func saveLockoutState(state LockoutState, masterHash string) error {
	// Ensure the config directory exists
	if err := ensureDirectories(); err != nil {
		return err
	}
	
	// Compute HMAC for the lockout state
	stateCopy := state
	stateCopy.HMAC = ""
	data, err := json.Marshal(stateCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal lockout state: %w", err)
	}
	
	// Set HMAC
	state.HMAC = computeHMAC(data, []byte(masterHash))
	
	// Marshal the complete state
	data, err = json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lockout state: %w", err)
	}
	
	// Create the file with restrictive permissions
	file, err := os.OpenFile(paths.LockFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create lockout file: %w", err)
	}
	defer file.Close()
	
	// Write the data
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to save lockout state: %w", err)
	}
	
	return nil
}

// checkLockoutState checks if the account is currently locked out
func checkLockoutState(masterHash string) error {
	// Load lockout state
	state, err := loadLockoutState()
	if err != nil {
		printWarning("Failed to load lockout state: %v", err)
		return nil // Continue if we can't load the state
	}
	
	// Check HMAC if state has attempts
	if state.FailedAttempts > 0 {
		// Verify HMAC
		stateCopy := state
		stateCopy.HMAC = ""
		data, err := json.Marshal(stateCopy)
		if err != nil {
			printWarning("Failed to verify lockout state integrity: %v", err)
			return nil // Continue if we can't verify
		}
		
		hmac := computeHMAC(data, []byte(masterHash))
		if !hmacEqual(hmac, state.HMAC) {
			printWarning("Lockout state integrity check failed")
			// Reset the state if integrity check fails
			state = LockoutState{}
			if err := saveLockoutState(state, masterHash); err != nil {
				printWarning("Failed to reset lockout state: %v", err)
			}
			return nil
		}
	}
	
	// Check if currently locked out
	if state.LockoutUntil.After(time.Now()) {
		waitTime := state.LockoutUntil.Sub(time.Now())
		return fmt.Errorf("account is locked out for %v due to too many failed attempts", waitTime.Round(time.Second))
	}
	
	// Reset failed attempts if lockout has expired
	if state.FailedAttempts > 0 && state.LockoutUntil.Before(time.Now()) {
		state.FailedAttempts = 0
		state.LockoutUntil = time.Time{}
		if err := saveLockoutState(state, masterHash); err != nil {
			printWarning("Failed to reset lockout state: %v", err)
		}
	}
	
	return nil
}

// recordFailedAttempt records a failed authentication attempt
func recordFailedAttempt(masterHash string) error {
	// Load current state
	state, err := loadLockoutState()
	if err != nil {
		return fmt.Errorf("failed to load lockout state: %w", err)
	}
	
	// Update state
	state.FailedAttempts++
	state.LastAttempt = time.Now()
	
	// Calculate lockout duration based on number of attempts
	if state.FailedAttempts >= maxAttempts {
		lockoutDuration := time.Duration(backoffFactor*state.FailedAttempts) * time.Minute
		state.LockoutUntil = time.Now().Add(lockoutDuration)
	}
	
	// Save updated state
	return saveLockoutState(state, masterHash)
}

// recordSuccessfulAttempt records a successful authentication attempt
func recordSuccessfulAttempt(masterHash string) error {
	// Load current state
	state, err := loadLockoutState()
	if err != nil {
		return fmt.Errorf("failed to load lockout state: %w", err)
	}
	
	// Reset state
	state.FailedAttempts = 0
	state.LastAttempt = time.Now()
	state.LockoutUntil = time.Time{}
	
	// Save updated state
	return saveLockoutState(state, masterHash)
}

// loadStore loads the password store from the storage file
func loadStore() (Store, error) {
	var store Store
	
	// Check if store file exists
	if _, err := os.Stat(paths.StoreFile); os.IsNotExist(err) {
		// Return empty store
		store.Creds = make(map[string]Credential)
		store.Version = appVersion
		store.LastUpdate = time.Now()
		return store, nil
	}
	
	// Read store file
	data, err := os.ReadFile(paths.StoreFile)
	if err != nil {
		return store, fmt.Errorf("failed to read store file: %w", err)
	}
	
	// Handle empty file
	if len(data) == 0 {
		store.Creds = make(map[string]Credential)
		store.Version = appVersion
		store.LastUpdate = time.Now()
		return store, nil
	}
	
	// Parse store
	if err := json.Unmarshal(data, &store); err != nil {
		return store, fmt.Errorf("failed to parse store data: %w", err)
	}
	
	// Skip HMAC check for empty store
	if store.MasterHash != "" && store.HMAC != "" {
		// Create a copy of the store without HMAC for verification
		storeCopy := store
		storeCopy.HMAC = ""
		dataCopy, _ := json.Marshal(storeCopy)
		
		// Verify HMAC
		hmac := computeHMAC(dataCopy, []byte(store.MasterHash))
		if !hmacEqual(hmac, store.HMAC) {
			return store, errors.New("data integrity check failed: HMAC mismatch")
		}
	}
	
	// Initialize credentials map if nil
	if store.Creds == nil {
		store.Creds = make(map[string]Credential)
	}
	
	return store, nil
}

// saveStore saves the store to the storage file
func saveStore(store Store) error {
	// Ensure the config directory exists
	if err := ensureDirectories(); err != nil {
		return err
	}
	
	// Update timestamp
	store.LastUpdate = time.Now()
	
	// Create a copy of the store without HMAC for HMAC calculation
	storeCopy := store
	storeCopy.HMAC = ""
	data, err := json.Marshal(storeCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal store: %w", err)
	}
	
	// Compute HMAC
	store.HMAC = computeHMAC(data, []byte(store.MasterHash))
	
	// Marshal the complete store
	data, err = json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal store: %w", err)
	}
	
	// Create backup before saving
	if _, err := os.Stat(paths.StoreFile); err == nil {
		backupPath := paths.StoreFile + ".backup." + time.Now().Format("20060102150405")
		if err := os.WriteFile(backupPath, data, 0600); err != nil {
			printWarning("Failed to create backup: %v", err)
		} else {
			// Clean up old backups
			cleanupBackups()
		}
	}
	
	// Create the file with restrictive permissions
	file, err := os.OpenFile(paths.StoreFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create store file: %w", err)
	}
	defer file.Close()
	
	// Write the data
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to save store: %w", err)
	}
	
	return nil
}

// setupMasterPassword sets up the master password for the first time
func setupMasterPassword() error {
	printInfo("Setting up master password")
	printInfo("Password must be at least %d characters and contain uppercase, lowercase, digits, and special characters", minPassLength)
	
	// Get new password
	pw, err := readInput("Enter new master password: ", true)
	if err != nil {
		return err
	}
	
	// Validate password strength
	if err := validatePasswordStrength(pw); err != nil {
		printError("Password too weak: %v", err)
		return err
	}
	
	// Confirm password
	confirmPw, err := readInput("Confirm master password: ", true)
	if err != nil {
		return err
	}
	
	// Check if passwords match
	if pw != confirmPw {
		// Zero out passwords
		secureZeroMemory([]byte(pw))
		secureZeroMemory([]byte(confirmPw))
		return errors.New("passwords do not match")
	}
	
	// Generate salt
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Derive key
	key, err := generateKey([]byte(pw), salt)
	if err != nil {
		return err
	}
	
	// Create hash
	hash := sha256.Sum256(key)
	hashStr := base64.StdEncoding.EncodeToString(hash[:])
	
	// Create store
	store := Store{
		MasterHash: hashStr,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Creds:      make(map[string]Credential),
		Version:    appVersion,
		LastUpdate: time.Now(),
	}
	
	// Save store
	if err := saveStore(store); err != nil {
		return err
	}
	
	// Encrypt config with master key
	if err := encryptConfig(key); err != nil {
		printWarning("Failed to encrypt config: %v", err)
	}
	
	// Initialize lockout state
	state := LockoutState{
		FailedAttempts: 0,
		LastAttempt:    time.Time{},
		LockoutUntil:   time.Time{},
	}
	if err := saveLockoutState(state, hashStr); err != nil {
		printWarning("Failed to initialize lockout state: %v", err)
	}
	
	// Update config
	config.FirstRun = false
	if err := saveConfig(); err != nil {
		return err
	}
	
	// Zero out sensitive data
	secureZeroMemory([]byte(pw))
	secureZeroMemory([]byte(confirmPw))
	secureZeroMemory(key)
	
	printSuccess("Master password set successfully")
	return nil
}

// verifyPassword verifies the entered master password
func verifyPassword(store Store) ([]byte, bool) {
	// Check lockout state
	if err := checkLockoutState(store.MasterHash); err != nil {
		printError("%v", err)
		return nil, false
	}
	
	attempts := 0
	for attempts < maxAttempts {
		pw, err := readInput("Enter master password: ", true)
		if err != nil {
			printError("Error reading password: %v", err)
			return nil, false
		}
		
		salt, err := base64.StdEncoding.DecodeString(store.Salt)
		if err != nil {
			printError("Error decoding salt: %v", err)
			return nil, false
		}
		
		key, err := generateKey([]byte(pw), salt)
		if err != nil {
			printError("Error generating key: %v", err)
			return nil, false
		}
		
		hash := sha256.Sum256(key)
		if hmacEqual(base64.StdEncoding.EncodeToString(hash[:]), store.MasterHash) {
			// Record successful attempt
			if err := recordSuccessfulAttempt(store.MasterHash); err != nil {
				printWarning("Failed to record successful attempt: %v", err)
			}
			
			// Zero out password
			secureZeroMemory([]byte(pw))
			
			return key, true
		}
		
		// Record failed attempt
		if err := recordFailedAttempt(store.MasterHash); err != nil {
			printWarning("Failed to record failed attempt: %v", err)
		}
		
		attempts++
		remainingAttempts := maxAttempts - attempts
		
		if remainingAttempts > 0 {
			printError("Invalid password. %d attempts remaining.", remainingAttempts)
			backoff := time.Duration(backoffFactor*attempts) * time.Second
			printWarning("Retrying in %v...", backoff)
			time.Sleep(backoff)
		} else {
			printError("Invalid password. No attempts remaining.")
		}
		
		// Zero out password
		secureZeroMemory([]byte(pw))
	}
	
	printError("Too many failed attempts. Account will be locked.")
	return nil, false
}

// changeMasterPassword changes the master password
func changeMasterPassword(store *Store) error {
	// Verify user is root
	if !isRoot() {
		return errors.New("changing master password requires root privileges")
	}
	
	printInfo("Changing master password (root only)")
	
	// Verify current master password
	currentKey, verified := verifyPassword(*store)
	if !verified {
		return errors.New("current master password verification failed")
	}
	
	// Get new password
	newPw, err := readInput("Enter new master password: ", true)
	if err != nil {
		return err
	}
	
	// Validate password strength
	if err := validatePasswordStrength(newPw); err != nil {
		printError("Password too weak: %v", err)
		return err
	}
	
	// Confirm password
	confirmPw, err := readInput("Confirm new master password: ", true)
	if err != nil {
		return err
	}
	
	// Check if passwords match
	if newPw != confirmPw {
		// Zero out passwords
		secureZeroMemory([]byte(newPw))
		secureZeroMemory([]byte(confirmPw))
		return errors.New("passwords do not match")
	}
	
	// Confirm the change
	confirm, err := readInput("This will change the master password and re-encrypt all credentials. Continue? (y/n): ", false)
	if err != nil {
		return err
	}
	
	if strings.ToLower(confirm) != "y" {
		// Zero out passwords
		secureZeroMemory([]byte(newPw))
		secureZeroMemory([]byte(confirmPw))
		return errors.New("operation cancelled")
	}
	
	// Create backup of current store
	backupPath := paths.StoreFile + ".backup." + time.Now().Format("20060102150405")
	data, err := json.MarshalIndent(*store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	
	printInfo("Created backup at %s", backupPath)
	
	// Generate new salt
	newSalt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}
	
	// Derive new key
	newKey, err := generateKey([]byte(newPw), newSalt)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}
	
	printInfo("Re-encrypting credentials...")
	
	// Show progress indicator
	if !secureFlag && isTerminal {
		go showProgress("Re-encrypting credentials", 2)
	}
	
	// Re-encrypt all credentials
	for service, cred := range store.Creds {
		// Decrypt with old key
		decPassword, err := decrypt(cred.Password, currentKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt credential for %s: %w", service, err)
		}
		
		// Encrypt with new key
		encPassword, err := encrypt([]byte(decPassword), newKey)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt credential for %s: %w", service, err)
		}
		
		// Update credential
		store.Creds[service] = Credential{
			Username: cred.Username,
			Password: encPassword,
			Created:  cred.Created,
			Updated:  time.Now(),
			Notes:    cred.Notes,
		}
		
		// Zero out decrypted password from memory
		secureZeroMemory([]byte(decPassword))
	}
	
	// Update store with new master hash and salt
	hash := sha256.Sum256(newKey)
	hashStr := base64.StdEncoding.EncodeToString(hash[:])
	store.MasterHash = hashStr
	store.Salt = base64.StdEncoding.EncodeToString(newSalt)
	
	// Save updated store
	if err := saveStore(*store); err != nil {
		return fmt.Errorf("failed to save updated store: %w", err)
	}
	
	// Re-encrypt config with new key
	if err := encryptConfig(newKey); err != nil {
		printWarning("Failed to re-encrypt config: %v", err)
	}
	
	// Reset lockout state
	state := LockoutState{
		FailedAttempts: 0,
		LastAttempt:    time.Now(),
		LockoutUntil:   time.Time{},
	}
	if err := saveLockoutState(state, hashStr); err != nil {
		printWarning("Failed to reset lockout state: %v", err)
	}
	
	// Zero out sensitive data
	secureZeroMemory([]byte(newPw))
	secureZeroMemory([]byte(confirmPw))
	secureZeroMemory(currentKey)
	secureZeroMemory(newKey)
	
	printSuccess("Master password changed successfully")
	return nil
}

// addCredential adds a new credential to the store
func addCredential(store *Store, key []byte) error {
	// Get service name
	service, err := readInput("Enter service name: ", false)
	if err != nil {
		return err
	}
	
	// Validate service name
	if service == "" {
		return errors.New("service name cannot be empty")
	}
	
	// Check if service already exists
	if _, exists := store.Creds[service]; exists {
		confirm, err := readInput(fmt.Sprintf("Service '%s' already exists. Update? (y/n): ", service), false)
		if err != nil {
			return err
		}
		
		if strings.ToLower(confirm) != "y" {
			return errors.New("operation cancelled")
		}
	}
	
	// Get username
	username, err := readInput("Enter username: ", false)
	if err != nil {
		return err
	}
	
	// Validate username
	if username == "" {
		return errors.New("username cannot be empty")
	}
	
	// Get password or generate one
	var password string
	genPass, err := readInput("Generate random password? (y/n): ", false)
	if err != nil {
		return err
	}
	
	if strings.ToLower(genPass) == "y" {
		// Get password length
		lenStr, err := readInput(fmt.Sprintf("Enter password length (default: %d): ", defaultPassLen), false)
		if err != nil {
			return err
		}
		
		passLen := defaultPassLen
		if lenStr != "" {
			fmt.Sscanf(lenStr, "%d", &passLen)
			if passLen < 8 {
				printWarning("Password length too short, using minimum length of 8")
				passLen = 8
			}
		}
		
		// Generate password
		password, err = generateRandomPassword(passLen)
		if err != nil {
			return err
		}
		
		// Show the generated password
		printSuccess("Generated password: %s", password)
		
		// Copy to clipboard
		copyToClipboardWithTimeout(password, clipTimeout)
	} else {
		// Get password manually
		password, err = readInput("Enter password: ", true)
		if err != nil {
			return err
		}
		
		// Validate password
		if password == "" {
			return errors.New("password cannot be empty")
		}
	}
	
	// Get optional notes
	notes, err := readInput("Enter notes (optional): ", false)
	if err != nil {
		return err
	}
	
	// Encrypt password
	encPassword, err := encrypt([]byte(password), key)
	if err != nil {
		return err
	}
	
	// Create or update credential
	now := time.Now()
	cred := store.Creds[service]
	
	if cred.Username == "" {
		// New credential
		store.Creds[service] = Credential{
			Username: username,
			Password: encPassword,
			Created:  now,
			Updated:  now,
			Notes:    notes,
		}
		printSuccess("Added credential for '%s'", service)
	} else {
		// Update existing credential
		store.Creds[service] = Credential{
			Username: username,
			Password: encPassword,
			Created:  cred.Created,
			Updated:  now,
			Notes:    notes,
		}
		printSuccess("Updated credential for '%s'", service)
	}
	
	// Zero out password
	secureZeroMemory([]byte(password))
	
	// Save store
	return saveStore(*store)
}

// deleteCredential deletes a credential from the store
func deleteCredential(store *Store) error {
	// Get service name
	service, err := readInput("Enter service name to delete: ", false)
	if err != nil {
		return err
	}
	
	// Check if service exists
	if _, exists := store.Creds[service]; !exists {
		return fmt.Errorf("service '%s' not found", service)
	}
	
	// Confirm deletion
	confirm, err := readInput(fmt.Sprintf("Are you sure you want to delete '%s'? (y/n): ", service), false)
	if err != nil {
		return err
	}
	
	if strings.ToLower(confirm) != "y" {
		return errors.New("operation cancelled")
	}
	
	// Delete credential
	delete(store.Creds, service)
	printSuccess("Deleted credential for '%s'", service)
	
	// Save store
	return saveStore(*store)
}

// rotatePassword generates a new password for an existing credential
func rotatePassword(store *Store, key []byte, service string, length int) error {
	// Check if service exists
	cred, exists := store.Creds[service]
	if !exists {
		return fmt.Errorf("service '%s' not found", service)
	}
	
	// Confirm rotation
	confirm, err := readInput(fmt.Sprintf("Rotate password for '%s'? (y/n): ", service), false)
	if err != nil {
		return err
	}
	
	if strings.ToLower(confirm) != "y" {
		return errors.New("operation cancelled")
	}
	
	// Generate new password
	password, err := generateRandomPassword(length)
	if err != nil {
		return err
	}
	
	// Show the generated password
	printSuccess("Generated new password: %s", password)
	
	// Copy to clipboard
	copyToClipboardWithTimeout(password, clipTimeout)
	
	// Encrypt password
	encPassword, err := encrypt([]byte(password), key)
	if err != nil {
		return err
	}
	
	// Update credential
	store.Creds[service] = Credential{
		Username: cred.Username,
		Password: encPassword,
		Created:  cred.Created,
		Updated:  time.Now(),
		Notes:    cred.Notes,
	}
	
	printSuccess("Rotated password for '%s'", service)
	
	// Zero out password
	secureZeroMemory([]byte(password))
	
	// Save store
	return saveStore(*store)
}

// searchCredentials searches for credentials by service name
func searchCredentials(store Store, searchTerm string) []string {
	var matches []string
	
	// Convert search term to lowercase for case-insensitive search
	searchLower := strings.ToLower(searchTerm)
	
	// Create regex for search
	regex, err := regexp.Compile(strings.ToLower(searchTerm))
	if err != nil {
		// If regex fails, fall back to simple substring search
		for service := range store.Creds {
			if strings.Contains(strings.ToLower(service), searchLower) {
				matches = append(matches, service)
			}
		}
	} else {
		// Use regex for search
		for service := range store.Creds {
			if regex.MatchString(strings.ToLower(service)) {
				matches = append(matches, service)
			}
		}
	}
	
	// Sort matches alphabetically
	sort.Strings(matches)
	
	return matches
}

// listCredentials lists all stored credentials
func listCredentials(store Store, key []byte) error {
	if len(store.Creds) == 0 {
		printInfo("No credentials stored")
		return nil
	}
	
	// Get services sorted alphabetically
	services := make([]string, 0, len(store.Creds))
	for service := range store.Creds {
		services = append(services, service)
	}
	
	// Sort services alphabetically
	sort.Strings(services)
	
	printInfo("Stored credentials:")
	fmt.Println()
	
	// Calculate column widths based on content
	serviceWidth := 20
	usernameWidth := 20
	updatedWidth := 20
	
	for _, service := range services {
		cred := store.Creds[service]
		if len(service) > serviceWidth {
			serviceWidth = len(service)
		}
		if len(cred.Username) > usernameWidth {
			usernameWidth = len(cred.Username)
		}
	}
	
	// Cap widths to reasonable values
	if serviceWidth > 40 {
		serviceWidth = 40
	}
	if usernameWidth > 30 {
		usernameWidth = 30
	}
	
	// Print header with dynamic widths
	headerFormat := fmt.Sprintf("%%-%ds | %%-%ds | %%-%ds | %%s\n", serviceWidth, usernameWidth, updatedWidth)
	fmt.Printf(headerFormat, "Service", "Username", "Last Updated", "Notes")
	fmt.Println(strings.Repeat("-", serviceWidth+usernameWidth+updatedWidth+15))
	
	// Print credentials with dynamic widths
	rowFormat := fmt.Sprintf("%%-%ds | %%-%ds | %%-%ds | %%s\n", serviceWidth, usernameWidth, updatedWidth)
	
	for _, service := range services {
		cred := store.Creds[service]
		
		// Format date
		updated := cred.Updated.Format("2006-01-02 15:04:05")
		if cred.Updated.IsZero() {
			updated = "N/A"
		}
		
		// Truncate fields if too long
		displayService := service
		if len(displayService) > serviceWidth {
			displayService = displayService[:serviceWidth-3] + "..."
		}
		
		displayUsername := cred.Username
		if len(displayUsername) > usernameWidth {
			displayUsername = displayUsername[:usernameWidth-3] + "..."
		}
		
		// Truncate notes if too long
		notes := cred.Notes
		if len(notes) > 30 {
			notes = notes[:27] + "..."
		}
		
		fmt.Printf(rowFormat, displayService, displayUsername, updated, notes)
	}
	
	fmt.Println()
	return nil
}

// viewCredential shows details for a specific credential
func viewCredential(store Store, key []byte) error {
	// Get service name
	service, err := readInput("Enter service name to view: ", false)
	if err != nil {
		return err
	}
	
	// Check if service exists
	cred, exists := store.Creds[service]
	if !exists {
		return fmt.Errorf("service '%s' not found", service)
	}
	
	// Decrypt password
	decPassword, err := decrypt(cred.Password, key)
	if err != nil {
		return err
	}
	
	// Format dates
	created := "N/A"
	if !cred.Created.IsZero() {
		created = cred.Created.Format("2006-01-02 15:04:05")
	}
	
	updated := "N/A"
	if !cred.Updated.IsZero() {
		updated = cred.Updated.Format("2006-01-02 15:04:05")
	}
	
	// Clear screen for better visibility
	clearScreen()
	
	// Print credential details with improved formatting
	fmt.Println()
	colorPrint(colorCyan+colorBold, "=== Credential Details ===\n\n")
	colorPrint(colorCyan, "Service:  %s\n", service)
	colorPrint(colorCyan, "Username: %s\n", cred.Username)
	colorPrint(colorCyan+colorBold, "Password: %s\n", decPassword)
	colorPrint(colorCyan, "Created:  %s\n", created)
	colorPrint(colorCyan, "Updated:  %s\n", updated)
	
	if cred.Notes != "" {
		colorPrint(colorCyan, "\nNotes:\n%s\n", cred.Notes)
	}
	
	fmt.Println()
	
	// Ask if user wants to copy password to clipboard
	copyPw, err := readInput("Copy password to clipboard? (y/n): ", false)
	if err != nil {
		return err
	}
	
	if strings.ToLower(copyPw) == "y" {
		copyToClipboardWithTimeout(decPassword, clipTimeout)
	}
	
	// Zero out decrypted password from memory
	secureZeroMemory([]byte(decPassword))
	
	return nil
}

// firstRunSetup performs first-time setup
func firstRunSetup() error {
	printInfo("Performing first-time setup")
	
	// Ensure directories exist
	if err := ensureDirectories(); err != nil {
		return err
	}
	
	// Create passman group
	if err := ensurePassmanGroup(); err != nil {
		printWarning("Failed to create group: %v", err)
		printWarning("Some features may not work correctly")
	}
	
	// Set up master password
	if err := setupMasterPassword(); err != nil {
		return err
	}
	
	// Set file permissions
	if err := setFilePermissions(); err != nil {
		printWarning("Failed to set file permissions: %v", err)
		printWarning("Some features may not work correctly")
	}
	
	printSuccess("First-time setup completed successfully")
	printInfo("Regular users can now use the application with the master password")
	printInfo("Only root can change the master password")
	
	return nil
}

// showHelp displays help information
func showHelp() {
	clearScreen()
	
	fmt.Println()
	colorPrint(colorCyan+colorBold, "=== Password Manager Help ===\n\n")
	
	colorPrint(colorYellow+colorBold, "Overview:\n")
	fmt.Println("This password manager securely stores your credentials using strong encryption.")
	fmt.Println("All operations require the master password for security.")
	fmt.Println()
	
	colorPrint(colorYellow+colorBold, "Command Line Options:\n")
	fmt.Println("  --help                 Show this help information")
	fmt.Println("  --version              Show version information")
	fmt.Println("  --secure               Suppress sensitive output (for scripts)")
	fmt.Println("  --search <term>        Search for credentials by service name")
	fmt.Println("  --rotate <service>     Rotate password for specified service")
	fmt.Println("  --length <num>         Length for generated passwords (default: 20)")
	fmt.Println("  --clip-timeout <sec>   Seconds before clipboard is cleared (default: 30)")
	fmt.Println()
	
	colorPrint(colorYellow+colorBold, "First Run:\n")
	fmt.Println("- First run must be performed as root")
	fmt.Println("- Sets up necessary files and permissions")
	fmt.Println("- Creates a master password")
	fmt.Println()
	
	colorPrint(colorYellow+colorBold, "Regular Usage:\n")
	fmt.Println("- Regular users can add, view, and manage credentials")
	fmt.Println("- All operations require the master password")
	fmt.Println("- Only root can change the master password")
	fmt.Println()
	
	colorPrint(colorYellow+colorBold, "Security Features:\n")
	fmt.Println("- AES-256 encryption for all credentials")
	fmt.Println("- Scrypt key derivation for password security")
	fmt.Println("- HMAC integrity verification")
	fmt.Println("- Memory protection to prevent sensitive data from being swapped")
	fmt.Println("- Automatic clipboard clearing")
	fmt.Println("- Persistent lockout for failed authentication attempts")
	fmt.Println()
	
	if isTerminal {
		fmt.Println("Press Enter to continue...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}

// showVersion displays version information
func showVersion() {
	fmt.Println()
	colorPrint(colorCyan+colorBold, "=== Password Manager ===\n")
	colorPrint(colorYellow, "Version: %s\n", appVersion)
	colorPrint(colorYellow, "Platform: %s\n", detectPlatform())
	fmt.Println()
}

// showAbout displays information about the application
func showAbout() {
	clearScreen()
	
	fmt.Println()
	colorPrint(colorCyan+colorBold, "=== Password Manager ===\n\n")
	colorPrint(colorYellow, "Version: %s\n", appVersion)
	colorPrint(colorYellow, "Platform: %s\n", config.Platform)
	colorPrint(colorYellow, "Config: %s\n", paths.ConfigFile)
	colorPrint(colorYellow, "Store: %s\n", paths.StoreFile)
	
	fmt.Println()
	fmt.Println("A secure password manager for storing and managing credentials.")
	fmt.Println("Optimized for Raspberry Pi, Debian, and Ubuntu systems.")
	fmt.Println()
	
	if isTerminal {
		fmt.Println("Press Enter to continue...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}

// drawMenuHeader draws a consistent header for the menu
func drawMenuHeader() {
	clearScreen()
	colorPrint(colorCyan+colorBold, "╔══════════════════════════════════════╗\n")
	colorPrint(colorCyan+colorBold, "║          PASSWORD MANAGER            ║\n")
	colorPrint(colorCyan+colorBold, "╚══════════════════════════════════════╝\n\n")
}

// mainMenu displays and handles the main menu
func mainMenu(store *Store, key []byte) {
	for {
		// Draw header
		drawMenuHeader()
		
		// Print menu options
		colorPrint(colorYellow, " 1. View all credentials\n")
		colorPrint(colorYellow, " 2. View specific credential\n")
		colorPrint(colorYellow, " 3. Add/update credential\n")
		colorPrint(colorYellow, " 4. Delete credential\n")
		colorPrint(colorYellow, " 5. Search credentials\n")
		colorPrint(colorYellow, " 6. Rotate password\n")
		
		// Root-only options
		if isRoot() {
			colorPrint(colorYellow, " 7. Change master password (root only)\n")
		}
		
		colorPrint(colorYellow, " 8. Help\n")
		colorPrint(colorYellow, " 9. About\n")
		colorPrint(colorYellow, " 0. Exit\n")
		fmt.Println()
		
		// Get user choice
		choice, err := readInput("Enter choice: ", false)
		if err != nil {
			printError("Error reading input: %v", err)
			continue
		}
		
		// Process choice
		switch choice {
		case "1":
			clearScreen()
			if err := listCredentials(*store, key); err != nil {
				printError("Error listing credentials: %v", err)
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "2":
			if err := viewCredential(*store, key); err != nil {
				printError("Error viewing credential: %v", err)
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "3":
			clearScreen()
			colorPrint(colorCyan+colorBold, "=== Add/Update Credential ===\n\n")
			if err := addCredential(store, key); err != nil {
				printError("Error adding credential: %v", err)
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "4":
			clearScreen()
			colorPrint(colorCyan+colorBold, "=== Delete Credential ===\n\n")
			if err := deleteCredential(store); err != nil {
				printError("Error deleting credential: %v", err)
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "5":
			clearScreen()
			colorPrint(colorCyan+colorBold, "=== Search Credentials ===\n\n")
			term, err := readInput("Enter search term: ", false)
			if err != nil {
				printError("Error reading input: %v", err)
				continue
			}
			
			matches := searchCredentials(*store, term)
			if len(matches) == 0 {
				printInfo("No matches found for '%s'", term)
			} else {
				printSuccess("Found %d matches for '%s':", len(matches), term)
				for i, service := range matches {
					fmt.Printf("%d. %s\n", i+1, service)
				}
				
				// Ask if user wants to view a specific match
				viewMatch, err := readInput("View a match? (Enter number or n): ", false)
				if err != nil {
					printError("Error reading input: %v", err)
					continue
				}
				
				if viewMatch != "n" && viewMatch != "N" {
					var index int
					fmt.Sscanf(viewMatch, "%d", &index)
					if index > 0 && index <= len(matches) {
						// View the selected credential
						service := matches[index-1]
						cred := store.Creds[service]
						
						// Decrypt password
						decPassword, err := decrypt(cred.Password, key)
						if err != nil {
							printError("Error decrypting password: %v", err)
							continue
						}
						
						// Format dates
						created := "N/A"
						if !cred.Created.IsZero() {
							created = cred.Created.Format("2006-01-02 15:04:05")
						}
						
						updated := "N/A"
						if !cred.Updated.IsZero() {
							updated = cred.Updated.Format("2006-01-02 15:04:05")
						}
						
						// Clear screen for better visibility
						clearScreen()
						
						// Print credential details
						fmt.Println()
						colorPrint(colorCyan+colorBold, "=== Credential Details ===\n\n")
						colorPrint(colorCyan, "Service:  %s\n", service)
						colorPrint(colorCyan, "Username: %s\n", cred.Username)
						colorPrint(colorCyan+colorBold, "Password: %s\n", decPassword)
						colorPrint(colorCyan, "Created:  %s\n", created)
						colorPrint(colorCyan, "Updated:  %s\n", updated)
						
						if cred.Notes != "" {
							colorPrint(colorCyan, "\nNotes:\n%s\n", cred.Notes)
						}
						
						fmt.Println()
						
						// Ask if user wants to copy password to clipboard
						copyPw, err := readInput("Copy password to clipboard? (y/n): ", false)
						if err != nil {
							printError("Error reading input: %v", err)
							continue
						}
						
						if strings.ToLower(copyPw) == "y" {
							copyToClipboardWithTimeout(decPassword, clipTimeout)
						}
						
						// Zero out decrypted password from memory
						secureZeroMemory([]byte(decPassword))
					}
				}
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "6":
			clearScreen()
			colorPrint(colorCyan+colorBold, "=== Rotate Password ===\n\n")
			service, err := readInput("Enter service name to rotate password: ", false)
			if err != nil {
				printError("Error reading input: %v", err)
				continue
			}
			
			lenStr, err := readInput(fmt.Sprintf("Enter password length (default: %d): ", defaultPassLen), false)
			if err != nil {
				printError("Error reading input: %v", err)
				continue
			}
			
			passLen := defaultPassLen
			if lenStr != "" {
				fmt.Sscanf(lenStr, "%d", &passLen)
				if passLen < 8 {
					printWarning("Password length too short, using minimum length of 8")
					passLen = 8
				}
			}
			
			if err := rotatePassword(store, key, service, passLen); err != nil {
				printError("Error rotating password: %v", err)
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "7":
			if isRoot() {
				clearScreen()
				colorPrint(colorCyan+colorBold, "=== Change Master Password ===\n\n")
				if err := changeMasterPassword(store); err != nil {
					printError("Error changing master password: %v", err)
				}
			} else {
				printError("This option requires root privileges")
			}
			
			if isTerminal {
				fmt.Println("Press Enter to continue...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
			}
			
		case "8":
			showHelp()
			
		case "9":
			showAbout()
			
		case "0":
			clearScreen()
			printInfo("Exiting...")
			return
			
		default:
			printError("Invalid choice")
			time.Sleep(1 * time.Second)
		}
	}
}

// handleCommandLine handles command line arguments
func handleCommandLine(store *Store, key []byte) bool {
	// Parse command line flags
	flag.Parse()
	
	// Check if help flag is set
	if helpFlag {
		showHelp()
		return true
	}
	
	// Check if version flag is set
	if versionFlag {
		showVersion()
		return true
	}
	
	// Check if search term is provided
	if searchTerm != "" {
		matches := searchCredentials(*store, searchTerm)
		if len(matches) == 0 {
			printInfo("No matches found for '%s'", searchTerm)
		} else {
			printSuccess("Found %d matches for '%s':", len(matches), searchTerm)
			for i, service := range matches {
				cred := store.Creds[service]
				fmt.Printf("%d. %s (Username: %s)\n", i+1, service, cred.Username)
			}
		}
		return true
	}
	
	// Check if rotate service is provided
	if rotateService != "" {
		if err := rotatePassword(store, key, rotateService, rotateLength); err != nil {
			printError("Error rotating password: %v", err)
		}
		return true
	}
	
	return false
}

// cleanup performs cleanup operations before exit
func cleanup() {
	// Unlock all locked memory
	unlockAllMemory()
	
	// Clear clipboard
	if err := clearClipboard(); err != nil {
		printWarning("Failed to clear clipboard: %v", err)
	}
	
	// Force garbage collection
	runtime.GC()
}

func main() {
	// Register cleanup function to run at exit
	defer cleanup()
	
	// Print welcome message
	printInfo("Password Manager v%s", appVersion)
	
	// Parse command line flags
	flag.Parse()
	
	// Load configuration
	if err := loadConfig(); err != nil {
		printError("Error loading configuration: %v", err)
		return
	}
	
	// Check if first run
	if config.FirstRun {
		// Check if running as root
		if !isRoot() {
			printError("Only root or sudoers may operate this tool. ")
			return
		}
		
		// Perform first-time setup
		if err := firstRunSetup(); err != nil {
			printError("Error during first-time setup: %v", err)
			return
		}
	}
	
	// Load password store
	store, err := loadStore()
	if err != nil {
		printError("Error loading password store: %v", err)
		return
	}
	
	// Check if master password is set
	if store.MasterHash == "" {
		printInfo("No master password set")
		
		// Check if running as root
		if !isRoot() {
			printError("Setting master password requires root privileges")
			return
		}
		
		// Set up master password
		if err := setupMasterPassword(); err != nil {
			printError("Error setting up master password: %v", err)
			return
		}
		
		// Reload store
		store, err = loadStore()
		if err != nil {
			printError("Error reloading password store: %v", err)
			return
		}
	}
	
	// Verify master password
	key, verified := verifyPassword(store)
	if !verified {
		return
	}
	
	// Decrypt config with master key
	if err := decryptConfig(key); err != nil {
		printWarning("Failed to decrypt config: %v", err)
	}
	
	// Handle command line arguments
	if handleCommandLine(&store, key) {
		return
	}
	
	// Show main menu
	mainMenu(&store, key)
}

// Done!

