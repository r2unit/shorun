// Package factory provides factory methods for creating connection managers
package factory

import (
	"fmt"

	"github.com/r2unit/shorun/pkg/connection"
	"github.com/r2unit/shorun/pkg/netconf"
	"github.com/r2unit/shorun/pkg/ssh"
	"github.com/r2unit/shorun/pkg/storage"
)

// CreateConnectionManager creates a connection manager based on the connection type
func CreateConnectionManager(config *connection.Config, storageManager *storage.Manager) (connection.Manager, error) {
	switch config.Type {
	case connection.SSH:
		return ssh.NewManager(config, storageManager)
	case connection.NETCONF:
		return netconf.NewManager(config, storageManager)
	default:
		return nil, fmt.Errorf("unsupported connection type: %s", config.Type)
	}
}
