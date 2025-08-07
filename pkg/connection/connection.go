// Package connection defines the interfaces for device connections
package connection

import (
	"context"
)

// Type represents the type of connection to use
type Type string

const (
	// SSH connection type
	SSH Type = "ssh"
	// NETCONF connection type
	NETCONF Type = "netconf"
)

// Config contains the configuration for a connection
type Config struct {
	// Host is the hostname or IP address of the device
	Host string
	// Port is the port to connect to
	Port int
	// Username is the username to authenticate with
	Username string
	// Password is the password to authenticate with
	Password string
	// Type is the type of connection to use
	Type Type
	// DeviceType is the type of device (cisco, juniper, etc.)
	DeviceType string
	// DeviceModel is the model of the device (ios, ios-xr, etc.)
	DeviceModel string
}

// Manager defines the interface for connection managers
type Manager interface {
	// Connect establishes a connection to the device
	Connect(ctx context.Context) error
	// Disconnect closes the connection to the device
	Disconnect() error
	// IsConnected returns true if the connection is established
	IsConnected() bool
	// GetConfig retrieves the configuration from the device
	GetConfig(ctx context.Context) (string, error)
	// ExecuteCommand executes a command on the device and returns the output
	ExecuteCommand(ctx context.Context, command string) (string, error)
	// SaveConfig saves the device configuration to a local file
	SaveConfig(ctx context.Context, path string) error
}
