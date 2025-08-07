// Package ssh provides functionality for SSH connections to devices
package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/r2unit/shorun/pkg/connection"
	"github.com/r2unit/shorun/pkg/storage"
)

// Manager implements the connection.Manager interface for SSH connections
type Manager struct {
	config     *connection.Config
	connected  bool
	conn       net.Conn
	storage    *storage.Manager
	deviceName string
}

// NewManager creates a new SSH connection manager
func NewManager(config *connection.Config, storageManager *storage.Manager) (*Manager, error) {
	if config.Type != connection.SSH {
		return nil, fmt.Errorf("invalid connection type: %s, expected: %s", config.Type, connection.SSH)
	}

	// Extract device name from host
	deviceName := config.Host
	if host, _, err := net.SplitHostPort(config.Host); err == nil {
		deviceName = host
	}

	return &Manager{
		config:     config,
		connected:  false,
		storage:    storageManager,
		deviceName: deviceName,
	}, nil
}

// Connect establishes an SSH connection to the device
func (m *Manager) Connect(ctx context.Context) error {
	// Determine the address to connect to
	addr := m.config.Host
	if !strings.Contains(addr, ":") {
		// If no port is specified, use the default SSH port or the one from config
		port := 22
		if m.config.Port != 0 {
			port = m.config.Port
		}
		addr = fmt.Sprintf("%s:%d", addr, port)
	}

	// In a real implementation, this would establish an SSH connection
	// For this simplified version, we'll just create a TCP connection
	// and pretend it's an SSH connection
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	// In a real implementation, we would perform SSH handshake and authentication here
	// For now, we'll just set the connection as established
	m.conn = conn
	m.connected = true

	fmt.Printf("Connected to %s (Note: This is a simplified implementation)\n", addr)
	return nil
}

// Disconnect closes the SSH connection
func (m *Manager) Disconnect() error {
	if !m.connected || m.conn == nil {
		return nil
	}

	err := m.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	m.connected = false
	m.conn = nil
	return nil
}

// IsConnected returns true if the SSH connection is established
func (m *Manager) IsConnected() bool {
	return m.connected && m.conn != nil
}

// ExecuteCommand executes a command on the device and returns the output
func (m *Manager) ExecuteCommand(ctx context.Context, command string) (string, error) {
	if !m.IsConnected() {
		return "", fmt.Errorf("not connected to server")
	}

	// In a real implementation, this would send the command over SSH and read the response
	// For this simplified version, we'll simulate responses for common commands

	// Simulate a delay for command execution
	time.Sleep(500 * time.Millisecond)

	// Simulate responses for common commands
	switch {
	case command == "show running-config" || command == "show configuration" || command == "show config":
		return "! Device Configuration\n! Generated on " + time.Now().Format(time.RFC3339) + "\n" +
			"hostname " + m.deviceName + "\n" +
			"!\n" +
			"interface GigabitEthernet0/0\n" +
			" ip address 192.168.1.1 255.255.255.0\n" +
			" no shutdown\n" +
			"!\n" +
			"ip route 0.0.0.0 0.0.0.0 192.168.1.254\n", nil

	case command == "cat /etc/network/interfaces":
		return "# This file describes the network interfaces available on your system\n" +
			"# and how to activate them. For more information, see interfaces(5).\n\n" +
			"source /etc/network/interfaces.d/*\n\n" +
			"# The loopback network interface\n" +
			"auto lo\n" +
			"iface lo inet loopback\n\n" +
			"# The primary network interface\n" +
			"auto eth0\n" +
			"iface eth0 inet static\n" +
			"  address 192.168.1.100\n" +
			"  netmask 255.255.255.0\n" +
			"  gateway 192.168.1.1\n", nil

	case command == "ip addr show":
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
			"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
			"    inet 127.0.0.1/8 scope host lo\n" +
			"       valid_lft forever preferred_lft forever\n" +
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n" +
			"    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n" +
			"    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n" +
			"       valid_lft forever preferred_lft forever\n", nil

	case command == "ip route show":
		return "default via 192.168.1.1 dev eth0 \n" +
			"192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 \n", nil

	default:
		return fmt.Sprintf("Command not recognized: %s\n", command), nil
	}
}

// GetConfig retrieves the configuration from the device
func (m *Manager) GetConfig(ctx context.Context) (string, error) {
	// For network devices, typically use "show running-config" or similar
	// For Linux/Debian, we might want to get specific configuration files
	// Here we'll implement a simple approach that works for network devices

	// Try common commands for network devices
	commands := []string{
		"show running-config",
		"show configuration",
		"show config",
	}

	var output string
	var err error

	for _, cmd := range commands {
		output, err = m.ExecuteCommand(ctx, cmd)
		if err == nil && len(output) > 0 {
			// If the command succeeded and returned output, use it
			return output, nil
		}
	}

	// If none of the network device commands worked, try Linux/Debian approach
	// For Linux/Debian, we could collect various config files
	linuxConfigs := []string{
		"cat /etc/network/interfaces",
		"ip addr show",
		"ip route show",
	}

	var configs []string
	for _, cmd := range linuxConfigs {
		output, err = m.ExecuteCommand(ctx, cmd)
		if err == nil && len(output) > 0 {
			configs = append(configs, fmt.Sprintf("=== %s ===\n%s\n\n", cmd, output))
		}
	}

	if len(configs) > 0 {
		return strings.Join(configs, ""), nil
	}

	return "", fmt.Errorf("failed to retrieve configuration: %w", err)
}

// SaveConfig saves the device configuration to a local file
func (m *Manager) SaveConfig(ctx context.Context, path string) error {
	// Get the configuration
	config, err := m.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// If a specific path is provided, save directly to that path
	if path != "" {
		// Create the directory if it doesn't exist
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Write the configuration to the file
		if err := os.WriteFile(path, []byte(config), 0644); err != nil {
			return fmt.Errorf("failed to write configuration to file: %w", err)
		}

		return nil
	}

	// Otherwise, use the storage manager
	if m.storage == nil {
		return fmt.Errorf("storage manager not initialized")
	}

	return m.storage.SaveConfig(m.deviceName, "running-config", config)
}
