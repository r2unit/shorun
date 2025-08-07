// Package storage provides functionality for storing device configurations
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manager handles storing device configurations
type Manager struct {
	// BaseDir is the base directory where configurations will be stored
	BaseDir string
}

// NewManager creates a new storage manager
func NewManager(baseDir string) (*Manager, error) {
	// If baseDir is empty, use the default directory
	if baseDir == "" {
		baseDir = "configs"
	}

	// Create the base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &Manager{
		BaseDir: baseDir,
	}, nil
}

// SaveConfig saves a device configuration to a file
func (m *Manager) SaveConfig(deviceName string, configType string, config string) error {
	// Create a directory for the device if it doesn't exist
	deviceDir := filepath.Join(m.BaseDir, deviceName)
	if err := os.MkdirAll(deviceDir, 0755); err != nil {
		return fmt.Errorf("failed to create device directory: %w", err)
	}

	// Create a filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(deviceDir, fmt.Sprintf("%s-%s.txt", configType, timestamp))

	// Write the configuration to the file
	if err := os.WriteFile(filename, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write configuration to file: %w", err)
	}

	return nil
}

// GetLatestConfig retrieves the latest configuration for a device
func (m *Manager) GetLatestConfig(deviceName string, configType string) (string, error) {
	deviceDir := filepath.Join(m.BaseDir, deviceName)

	// Check if the device directory exists
	if _, err := os.Stat(deviceDir); os.IsNotExist(err) {
		return "", fmt.Errorf("no configurations found for device %s", deviceName)
	}

	// Get all configuration files for the device
	pattern := filepath.Join(deviceDir, fmt.Sprintf("%s-*.txt", configType))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to list configuration files: %w", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no %s configurations found for device %s", configType, deviceName)
	}

	// Find the latest file (assuming the timestamp in the filename allows for lexicographical sorting)
	latestFile := matches[len(matches)-1]
	for _, file := range matches {
		if file > latestFile {
			latestFile = file
		}
	}

	// Read the configuration from the file
	config, err := os.ReadFile(latestFile)
	if err != nil {
		return "", fmt.Errorf("failed to read configuration file: %w", err)
	}

	return string(config), nil
}
