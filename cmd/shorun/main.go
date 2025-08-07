package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/r2unit/shorun/pkg/connection"
	"github.com/r2unit/shorun/pkg/factory"
	"github.com/r2unit/shorun/pkg/storage"
)

func main() {
	host := flag.String("host", "", "Host to connect to (required)")
	port := flag.Int("port", 0, "Port to connect to (default: 22 for SSH, 830 for NETCONF)")
	username := flag.String("username", "", "Username for authentication (required)")
	password := flag.String("password", "", "Password for authentication (required)")
	connType := flag.String("type", "ssh", "Connection type (ssh or netconf)")
	deviceType := flag.String("device-type", "", "Device type (cisco, juniper, arista, huawei, generic)")
	deviceModel := flag.String("device-model", "", "Device model (ios, ios-xr, nxos, junos, eos, vrp)")
	command := flag.String("command", "", "Command to execute (optional)")
	getConfig := flag.Bool("get-config", false, "Get device configuration")
	saveConfig := flag.String("save-config", "", "Save configuration to file (specify path or leave empty for default)")
	configDir := flag.String("config-dir", "configs", "Directory to store configurations")

	// Parse command-line flags
	flag.Parse()

	// Validate required flags
	if *host == "" {
		fmt.Println("Error: host is required")
		flag.Usage()
		os.Exit(1)
	}
	if *username == "" {
		fmt.Println("Error: username is required")
		flag.Usage()
		os.Exit(1)
	}
	if *password == "" {
		fmt.Println("Error: password is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate connection type
	var connTypeEnum connection.Type
	switch strings.ToLower(*connType) {
	case "ssh":
		connTypeEnum = connection.SSH
	case "netconf":
		connTypeEnum = connection.NETCONF
	default:
		fmt.Printf("Error: invalid connection type: %s (must be ssh or netconf)\n", *connType)
		flag.Usage()
		os.Exit(1)
	}

	// Create connection config
	config := &connection.Config{
		Host:        *host,
		Port:        *port,
		Username:    *username,
		Password:    *password,
		Type:        connTypeEnum,
		DeviceType:  *deviceType,
		DeviceModel: *deviceModel,
	}

	// Create storage manager
	storageManager, err := storage.NewManager(*configDir)
	if err != nil {
		fmt.Printf("Error creating storage manager: %v\n", err)
		os.Exit(1)
	}

	// Create connection manager
	connManager, err := factory.CreateConnectionManager(config, storageManager)
	if err != nil {
		fmt.Printf("Error creating connection manager: %v\n", err)
		os.Exit(1)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to the device
	fmt.Printf("Connecting to %s using %s...\n", *host, *connType)
	if err := connManager.Connect(ctx); err != nil {
		fmt.Printf("Error connecting to device: %v\n", err)
		os.Exit(1)
	}
	defer connManager.Disconnect()

	fmt.Printf("Connected to %s\n", *host)

	// Execute command if specified
	if *command != "" {
		fmt.Printf("Executing command: %s\n", *command)
		output, err := connManager.ExecuteCommand(ctx, *command)
		if err != nil {
			fmt.Printf("Error executing command: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Command output:")
		fmt.Println(output)
	}

	// Get configuration if requested
	if *getConfig {
		fmt.Println("Getting device configuration...")
		config, err := connManager.GetConfig(ctx)
		if err != nil {
			fmt.Printf("Error getting configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Device configuration:")
		fmt.Println(config)
	}

	// Save configuration if requested
	if *saveConfig != "" || *getConfig {
		fmt.Println("Saving device configuration...")
		err := connManager.SaveConfig(ctx, *saveConfig)
		if err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration saved successfully")
	}

	fmt.Println("Done")
}
