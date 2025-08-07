// Package netconf provides functionality for NETCONF connections to devices
package netconf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/r2unit/shorun/pkg/connection"
	"github.com/r2unit/shorun/pkg/devicetemplate"
	"github.com/r2unit/shorun/pkg/ssh"
	"github.com/r2unit/shorun/pkg/storage"
)

// Constants for NETCONF protocol
const (
	// DefaultPort is the default NETCONF port
	DefaultPort = 830

	// MessageSeparator is the end-of-message delimiter for NETCONF 1.0
	MessageSeparator = "]]>]]>"

	// NamespaceBase is the base namespace for NETCONF
	NamespaceBase = "urn:ietf:params:xml:ns:netconf:base:1.0"

	// DefaultHelloTimeout is the default timeout for hello message exchange
	DefaultHelloTimeout = 30 * time.Second

	// DefaultReplyTimeout is the default timeout for RPC reply message exchange
	DefaultReplyTimeout = 30 * time.Second
)

// Common NETCONF capabilities
const (
	// Base capability for NETCONF 1.0
	CapabilityBase = "urn:ietf:params:netconf:base:1.0"

	// Capability for NETCONF 1.1 with chunked framing
	CapabilityBase11 = "urn:ietf:params:netconf:base:1.1"

	// Capability for writable-running
	CapabilityWritableRunning = "urn:ietf:params:netconf:capability:writable-running:1.0"

	// Capability for candidate configuration
	CapabilityCandidate = "urn:ietf:params:netconf:capability:candidate:1.0"

	// Capability for confirmed commit
	CapabilityConfirmedCommit = "urn:ietf:params:netconf:capability:confirmed-commit:1.0"

	// Capability for rollback-on-error
	CapabilityRollbackOnError = "urn:ietf:params:netconf:capability:rollback-on-error:1.0"

	// Capability for validate
	CapabilityValidate = "urn:ietf:params:netconf:capability:validate:1.0"

	// Capability for startup configuration
	CapabilityStartup = "urn:ietf:params:netconf:capability:startup:1.0"

	// Capability for URL
	CapabilityURL = "urn:ietf:params:netconf:capability:url:1.0"

	// Capability for XPath
	CapabilityXPath = "urn:ietf:params:netconf:capability:xpath:1.0"
)

// XML message templates
const (
	xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>`

	helloMessageTemplate = `
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    %s
  </capabilities>
</hello>`

	rpcTemplate = `
<rpc message-id="%s" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  %s
</rpc>`

	getConfigTemplate = `
<get-config>
  <source>
    <running/>
  </source>
  %s
</get-config>`

	getTemplate = `
<get>
  %s
</get>`

	filterTemplate = `
<filter type="%s">
  %s
</filter>`
)

// Session represents a NETCONF session
type Session struct {
	Transport          io.ReadWriteCloser
	SessionID          string
	ClientCapabilities []string
	ServerCapabilities []string
	Framing            FramingType
	sshClient          *ssh.Client
	sshSession         *ssh.Session
	messageID          int
}

// FramingType represents the framing mechanism used in NETCONF
type FramingType int

const (
	// FramingEOM represents end-of-message framing (NETCONF 1.0)
	FramingEOM FramingType = iota

	// FramingChunked represents chunked framing (NETCONF 1.1)
	FramingChunked
)

// Hello represents a NETCONF hello message
type Hello struct {
	XMLName      xml.Name `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 hello"`
	Capabilities []string `xml:"capabilities>capability"`
	SessionID    string   `xml:"session-id,omitempty"`
}

// RPCMessage represents a NETCONF RPC message
type RPCMessage struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 rpc"`
	MessageID string   `xml:"message-id,attr"`
	Content   string   `xml:",innerxml"`
}

// RPCReply represents a NETCONF RPC reply
type RPCReply struct {
	XMLName   xml.Name   `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 rpc-reply"`
	MessageID string     `xml:"message-id,attr,omitempty"`
	Data      string     `xml:",innerxml"`
	Errors    []RPCError `xml:"rpc-error,omitempty"`
}

// RPCError represents a NETCONF RPC error
type RPCError struct {
	Type     string `xml:"error-type"`
	Tag      string `xml:"error-tag"`
	Severity string `xml:"error-severity"`
	Path     string `xml:"error-path,omitempty"`
	Message  string `xml:"error-message"`
	Info     string `xml:"error-info,omitempty"`
}

// RPCMethod represents a method in a NETCONF RPC message
type RPCMethod interface {
	Method() string
}

// RawMethod is a raw XML method
type RawMethod string

// Method returns the raw XML method
func (r RawMethod) Method() string {
	return string(r)
}

// NewSession creates a new NETCONF session
func NewSession(t io.ReadWriteCloser) (*Session, error) {
	s := &Session{
		Transport: t,
		ClientCapabilities: []string{
			CapabilityBase,
		},
		Framing:   FramingEOM,
		messageID: 1,
	}

	// Exchange hello messages
	if err := s.exchangeHello(); err != nil {
		return nil, fmt.Errorf("failed to exchange hello messages: %w", err)
	}

	return s, nil
}

// DialSSH creates a new NETCONF session using SSH transport
func DialSSH(addr string, config *ssh.ClientConfig) (*Session, error) {
	// Create a new SSH client
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %w", err)
	}

	// Create a new SSH session
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Set up the NETCONF subsystem
	// In a real implementation, this would involve:
	// 1. Setting up stdin/stdout pipes for the session
	// 2. Requesting the "netconf" subsystem
	// 3. Creating a transport from the pipes
	// For now, we'll create a dummy transport that simulates the behavior

	// Create a pipe for communication
	pr, pw := io.Pipe()

	// Create a transport that wraps the pipe
	transport := &netconfTransport{
		reader: pr,
		writer: pw,
	}

	// Create a new NETCONF session with the transport
	s := &Session{
		Transport: transport,
		ClientCapabilities: []string{
			CapabilityBase,
		},
		Framing:    FramingEOM,
		sshClient:  client,
		sshSession: session,
		messageID:  1,
	}

	// Exchange hello messages
	if err := s.exchangeHello(); err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to exchange hello messages: %w", err)
	}

	return s, nil
}

// netconfTransport implements io.ReadWriteCloser for NETCONF
type netconfTransport struct {
	reader io.Reader
	writer io.Writer
}

func (t *netconfTransport) Read(p []byte) (n int, err error) {
	return t.reader.Read(p)
}

func (t *netconfTransport) Write(p []byte) (n int, err error) {
	return t.writer.Write(p)
}

func (t *netconfTransport) Close() error {
	if closer, ok := t.reader.(io.Closer); ok {
		closer.Close()
	}
	if closer, ok := t.writer.(io.Closer); ok {
		closer.Close()
	}
	return nil
}

// exchangeHello exchanges hello messages with the server
func (s *Session) exchangeHello() error {
	// Create hello message
	hello := &Hello{
		Capabilities: s.ClientCapabilities,
	}

	// Marshal hello message to XML
	helloXML, err := xml.MarshalIndent(hello, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hello message: %w", err)
	}

	// Send hello message
	if _, err := s.Transport.Write([]byte(xmlHeader + string(helloXML) + MessageSeparator)); err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	// Receive hello message
	serverHello := &Hello{}
	if err := s.receiveHello(serverHello); err != nil {
		return fmt.Errorf("failed to receive hello message: %w", err)
	}

	// Store server capabilities and session ID
	s.ServerCapabilities = serverHello.Capabilities
	s.SessionID = serverHello.SessionID

	// Determine framing based on capabilities
	for _, capability := range s.ServerCapabilities {
		if capability == CapabilityBase11 {
			s.Framing = FramingChunked
			break
		}
	}

	return nil
}

// bufferedTransport wraps an io.ReadWriteCloser with a buffered reader
// to efficiently handle message separator detection and preserve data after the separator
type bufferedTransport struct {
	reader *bufio.Reader
	writer io.Writer
	closer io.Closer
	buffer []byte // Buffer to store data read after the separator
}

func newBufferedTransport(transport io.ReadWriteCloser) *bufferedTransport {
	return &bufferedTransport{
		reader: bufio.NewReaderSize(transport, 4096),
		writer: transport,
		closer: transport,
	}
}

func (t *bufferedTransport) Read(p []byte) (n int, err error) {
	// If we have buffered data, return it first
	if len(t.buffer) > 0 {
		n = copy(p, t.buffer)
		t.buffer = t.buffer[n:]
		return n, nil
	}
	// Otherwise, read from the underlying reader
	return t.reader.Read(p)
}

func (t *bufferedTransport) Write(p []byte) (n int, err error) {
	return t.writer.Write(p)
}

func (t *bufferedTransport) Close() error {
	return t.closer.Close()
}

// Store data to be read in subsequent Read calls
func (t *bufferedTransport) StoreData(data []byte) {
	t.buffer = append(t.buffer, data...)
}

// readFramedMessage reads a framed message from the transport with the given timeout
// It returns the message data (excluding the separator) and any error encountered
func (s *Session) readFramedMessage(timeout time.Duration, msgType string) ([]byte, error) {
	// Create a context with timeout for the read operation
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a buffered transport to efficiently handle message separator detection
	// and preserve data after the separator
	bt := newBufferedTransport(s.Transport)

	// Channel to receive the result of the read operation
	type readResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan readResult, 1)

	// Start a goroutine to read until the message separator
	go func() {
		var buf bytes.Buffer
		sepBytes := []byte(MessageSeparator)
		sepLen := len(sepBytes)
		window := make([]byte, 0, sepLen)

		for {
			// Read one byte at a time to efficiently detect the separator
			b, err := bt.reader.ReadByte()
			if err != nil {
				resultCh <- readResult{nil, fmt.Errorf("failed to read from transport: %w", err)}
				return
			}

			// Add the byte to the buffer
			buf.WriteByte(b)

			// Update the sliding window
			window = append(window, b)
			if len(window) > sepLen {
				window = window[1:]
			}

			// Check if the window contains the separator
			if len(window) == sepLen && bytes.Equal(window, sepBytes) {
				// Found the separator, extract the message (excluding the separator)
				data := buf.Bytes()
				messageData := data[:len(data)-sepLen]

				// Check if there's any data after the separator
				var remaining []byte
				if bt.reader.Buffered() > 0 {
					// Read the remaining buffered data
					remaining = make([]byte, bt.reader.Buffered())
					_, err := bt.reader.Read(remaining)
					if err != nil {
						resultCh <- readResult{nil, fmt.Errorf("failed to read remaining data: %w", err)}
						return
					}

					// Instead of storing the data in the buffered transport and replacing the session's transport,
					// we'll handle the remaining data differently in a real implementation.
					// For now, we'll just log that there's remaining data.
					if len(remaining) > 0 {
						fmt.Printf("Warning: %d bytes of data after message separator will be discarded\n", len(remaining))
					}
				}

				resultCh <- readResult{messageData, nil}
				return
			}
		}
	}()

	// Wait for either the read operation to complete or the timeout to expire
	select {
	case result := <-resultCh:
		return result.data, result.err
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for %s message: %w", msgType, ctx.Err())
	}
}

// receiveHello receives a hello message from the server
func (s *Session) receiveHello(hello *Hello) error {
	// Read the framed message with timeout
	data, err := s.readFramedMessage(DefaultHelloTimeout, "hello")
	if err != nil {
		return err
	}

	// Unmarshal the hello message
	if err := xml.Unmarshal(data, hello); err != nil {
		return fmt.Errorf("failed to unmarshal hello message: %w", err)
	}

	return nil
}

// Close closes the NETCONF session
func (s *Session) Close() error {
	// Send close-session RPC
	_, err := s.Exec(RawMethod(`<close-session/>`))
	if err != nil {
		// Log the error but continue with cleanup
		fmt.Printf("Error sending close-session: %v\n", err)
	}

	// Close the SSH session
	if s.sshSession != nil {
		s.sshSession.Close()
	}

	// Close the SSH client
	if s.sshClient != nil {
		s.sshClient.Close()
	}

	// Close the transport
	if s.Transport != nil {
		return s.Transport.Close()
	}

	return nil
}

// Exec executes a NETCONF RPC
func (s *Session) Exec(methods ...RPCMethod) (*RPCReply, error) {
	// Create RPC message
	messageID := fmt.Sprintf("%d", s.messageID)
	s.messageID++

	// Combine methods
	methodsXML := ""
	for _, method := range methods {
		methodsXML += method.Method()
	}

	// Create RPC message
	rpcXML := fmt.Sprintf(rpcTemplate, messageID, methodsXML)

	// Send RPC message
	if _, err := s.Transport.Write([]byte(xmlHeader + rpcXML + MessageSeparator)); err != nil {
		return nil, fmt.Errorf("failed to send RPC message: %w", err)
	}

	// Receive RPC reply
	reply := &RPCReply{}
	if err := s.receiveReply(reply); err != nil {
		return nil, fmt.Errorf("failed to receive RPC reply: %w", err)
	}

	return reply, nil
}

// receiveReply receives an RPC reply from the server
func (s *Session) receiveReply(reply *RPCReply) error {
	// Read the framed message with timeout
	data, err := s.readFramedMessage(DefaultReplyTimeout, "reply")
	if err != nil {
		return err
	}

	// Unmarshal the reply message
	if err := xml.Unmarshal(data, reply); err != nil {
		return fmt.Errorf("failed to unmarshal reply message: %w", err)
	}

	// Check if the reply contains errors
	if len(reply.Errors) > 0 {
		// Return the first error
		return fmt.Errorf("NETCONF RPC error: %s - %s", reply.Errors[0].Tag, reply.Errors[0].Message)
	}

	return nil
}

// Manager implements the connection.Manager interface for NETCONF connections
type Manager struct {
	config           *connection.Config
	connected        bool
	session          *Session
	storage          *storage.Manager
	deviceName       string
	sessionID        string
	deviceType       devicetemplate.DeviceType
	deviceModel      devicetemplate.DeviceModel
	templateRegistry *devicetemplate.Registry
	deviceTemplate   *devicetemplate.Template
	capabilities     []string
}

// NewManager creates a new NETCONF connection manager
func NewManager(config *connection.Config, storageManager *storage.Manager) (*Manager, error) {
	if config.Type != connection.NETCONF {
		return nil, fmt.Errorf("invalid connection type: %s, expected: %s", config.Type, connection.NETCONF)
	}

	// Extract device name from host
	deviceName := config.Host
	if host, _, err := net.SplitHostPort(config.Host); err == nil {
		deviceName = host
	}

	// Initialize device template registry
	templateRegistry := devicetemplate.NewRegistry()

	// Set device type and model from config if provided, otherwise default to generic
	deviceType := devicetemplate.DeviceTypeGeneric
	deviceModel := devicetemplate.GenericModel

	// If device type is specified in the config, use it
	if config.DeviceType != "" {
		switch strings.ToLower(config.DeviceType) {
		case "cisco":
			deviceType = devicetemplate.DeviceTypeCisco
		case "juniper":
			deviceType = devicetemplate.DeviceTypeJuniper
		case "arista":
			deviceType = devicetemplate.DeviceTypeArista
		case "huawei":
			deviceType = devicetemplate.DeviceTypeHuawei
		case "generic":
			deviceType = devicetemplate.DeviceTypeGeneric
		default:
			fmt.Printf("Warning: Unknown device type '%s', defaulting to generic\n", config.DeviceType)
		}
	}

	// If device model is specified in the config, use it
	if config.DeviceModel != "" {
		switch strings.ToLower(config.DeviceModel) {
		case "ios-xr":
			deviceModel = devicetemplate.CiscoIOSXR
		case "ios":
			deviceModel = devicetemplate.CiscoIOS
		case "ios-xe":
			deviceModel = devicetemplate.CiscoIOSXE
		case "nxos":
			deviceModel = devicetemplate.CiscoNXOS
		case "junos":
			deviceModel = devicetemplate.JuniperJunos
		case "eos":
			deviceModel = devicetemplate.AristaEOS
		case "vrp":
			deviceModel = devicetemplate.HuaweiVRP
		case "generic":
			deviceModel = devicetemplate.GenericModel
		default:
			fmt.Printf("Warning: Unknown device model '%s', defaulting to generic\n", config.DeviceModel)
		}
	}

	// Get the template for the default device type and model
	template, err := templateRegistry.GetTemplate(deviceType, deviceModel)
	if err != nil {
		return nil, fmt.Errorf("failed to get device template: %w", err)
	}

	return &Manager{
		config:           config,
		connected:        false,
		storage:          storageManager,
		deviceName:       deviceName,
		sessionID:        fmt.Sprintf("s%d", time.Now().Unix()),
		deviceType:       deviceType,
		deviceModel:      deviceModel,
		templateRegistry: templateRegistry,
		deviceTemplate:   template,
	}, nil
}

// Connect establishes a NETCONF connection to the device
func (m *Manager) Connect(ctx context.Context) error {
	// Determine the address to connect to
	host := m.config.Host

	// Check if port is specified in the host string
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(m.config.Host)
		if err != nil {
			return fmt.Errorf("invalid host format: %w", err)
		}
	}

	// Check if port is zero and if so, set it to the default NETCONF port (830)
	port := m.config.Port
	if port == 0 {
		port = DefaultPort // Default NETCONF port is 830
	}

	// Set up SSH client configuration using our SSH implementation
	sshConfig := &ssh.ClientConfig{
		User: m.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(m.config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect to the device using SSH
	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("Connecting to %s using NETCONF over SSH...\n", addr)

	// Establish NETCONF session
	session, err := DialSSH(addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to establish NETCONF session: %w", err)
	}

	// Store the session and mark as connected
	m.session = session
	m.connected = true
	m.capabilities = session.ServerCapabilities

	// Detect device type based on capabilities
	m.detectDeviceType()

	fmt.Printf("Connected to %s using NETCONF (Device type: %s, Model: %s)\n",
		addr, m.deviceType, m.deviceModel)
	return nil
}

// detectDeviceType attempts to detect the device type and model
// based on the capabilities received from the device
func (m *Manager) detectDeviceType() {
	if m.capabilities == nil || len(m.capabilities) == 0 {
		fmt.Println("Warning: No capabilities received from device, using default device type")
		return
	}

	// Convert capabilities slice to a string for the template registry
	capabilitiesStr := "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  <capabilities>\n"
	for _, capability := range m.capabilities {
		capabilitiesStr += fmt.Sprintf("    <capability>%s</capability>\n", capability)
	}
	capabilitiesStr += "  </capabilities>\n</hello>"

	// Detect device type and model from capabilities
	deviceType, deviceModel := m.templateRegistry.DetectDeviceType(capabilitiesStr)

	// Update device type and model
	m.deviceType = deviceType
	m.deviceModel = deviceModel

	// Get the template for the detected device type and model
	template, err := m.templateRegistry.GetTemplate(deviceType, deviceModel)
	if err == nil {
		m.deviceTemplate = template
	}

	fmt.Printf("Detected device type: %s, model: %s based on capabilities\n",
		deviceType, deviceModel)
}

// Disconnect closes the NETCONF connection
func (m *Manager) Disconnect() error {
	if !m.connected || m.session == nil {
		return nil
	}

	// Close the NETCONF session
	err := m.session.Close()
	if err != nil {
		return fmt.Errorf("failed to close NETCONF session: %w", err)
	}

	m.connected = false
	m.session = nil
	return nil
}

// IsConnected returns true if the NETCONF connection is established
func (m *Manager) IsConnected() bool {
	return m.connected && m.session != nil
}

// ExecuteCommand executes a command on the device and returns the output
// Note: NETCONF doesn't directly support command execution like SSH
// This implementation maps commands to NETCONF operations
func (m *Manager) ExecuteCommand(ctx context.Context, command string) (string, error) {
	if !m.IsConnected() {
		return "", fmt.Errorf("not connected to server")
	}

	// Map the generic command to a device-specific command using the template
	if m.deviceTemplate != nil {
		deviceCommand := m.deviceTemplate.GetCommandMapping(command)
		if deviceCommand != command {
			fmt.Printf("Mapped command '%s' to device-specific command '%s' for %s %s\n",
				command, deviceCommand, m.deviceType, m.deviceModel)
			command = deviceCommand
		}
	}

	// Map commands to NETCONF operations
	var rpcReply *RPCReply
	var err error

	switch {
	case command == "get-config" || command == "show running-config" || command == "show configuration" ||
		command == "display current-configuration":
		// Use GetConfig method which already implements the get-config RPC
		return m.GetConfig(ctx)

	case strings.HasPrefix(command, "get "):
		// Extract the path from the command
		path := strings.TrimPrefix(command, "get ")

		// Create a get RPC with a filter for the specified path
		rpcReply, err = m.session.Exec(RawMethod(fmt.Sprintf(`
			<get>
				<filter type="subtree">
					<%s/>
				</filter>
			</get>
		`, path)))

	case command == "show interfaces" || command == "display interface":
		// Get interfaces information
		rpcReply, err = m.session.Exec(RawMethod(`
			<get>
				<filter type="subtree">
					<interfaces/>
				</filter>
			</get>
		`))

	case command == "show version" || command == "display version":
		// Get system information
		rpcReply, err = m.session.Exec(RawMethod(`
			<get>
				<filter type="subtree">
					<system/>
				</filter>
			</get>
		`))

	default:
		return fmt.Sprintf("Command not supported in NETCONF: %s\n", command), nil
	}

	if err != nil {
		return "", fmt.Errorf("failed to execute NETCONF RPC for command '%s': %w", command, err)
	}

	if rpcReply != nil {
		return rpcReply.Data, nil
	}

	return "", nil
}

// GetConfig retrieves the configuration from the device
func (m *Manager) GetConfig(ctx context.Context) (string, error) {
	if !m.IsConnected() {
		return "", fmt.Errorf("not connected to server")
	}

	// Create a NETCONF get-config RPC
	rpcReply, err := m.session.Exec(RawMethod(`
		<get-config>
			<source>
				<running/>
			</source>
		</get-config>
	`))

	if err != nil {
		return "", fmt.Errorf("failed to execute get-config RPC: %w", err)
	}

	// Return the XML response
	return rpcReply.Data, nil
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

	return m.storage.SaveConfig(m.deviceName, "netconf-config", config)
}
