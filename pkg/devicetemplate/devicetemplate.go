// Package devicetemplate provides functionality for device-specific templates
package devicetemplate

import (
	"fmt"
	"strings"
)

// DeviceType represents the type of network device
type DeviceType string

// Known device types
const (
	DeviceTypeUnknown DeviceType = "unknown"
	DeviceTypeCisco   DeviceType = "cisco"
	DeviceTypeJuniper DeviceType = "juniper"
	DeviceTypeArista  DeviceType = "arista"
	DeviceTypeHuawei  DeviceType = "huawei"
	DeviceTypeGeneric DeviceType = "generic"
)

// DeviceModel represents the model of a network device
type DeviceModel string

// Known device models
const (
	// Cisco models
	CiscoIOSXR DeviceModel = "ios-xr"
	CiscoIOS   DeviceModel = "ios"
	CiscoNXOS  DeviceModel = "nxos"
	CiscoIOSXE DeviceModel = "ios-xe"

	// Juniper models
	JuniperJunos DeviceModel = "junos"

	// Arista models
	AristaEOS DeviceModel = "eos"

	// Huawei models
	HuaweiVRP DeviceModel = "vrp"

	// Generic model
	GenericModel DeviceModel = "generic"
)

// Template contains device-specific commands and parameters
type Template struct {
	// Type is the device type
	Type DeviceType

	// Model is the device model
	Model DeviceModel

	// GetConfigCommand is the command to retrieve the device configuration
	GetConfigCommand string

	// GetConfigXPath is the XPath to retrieve the device configuration
	GetConfigXPath string

	// DetectionPatterns are regex patterns to detect this device type/model from capabilities
	DetectionPatterns []string

	// CommandMappings maps generic commands to device-specific commands
	CommandMappings map[string]string
}

// Registry stores all known device templates
type Registry struct {
	templates []Template
}

// NewRegistry creates a new device template registry with default templates
func NewRegistry() *Registry {
	registry := &Registry{
		templates: []Template{
			// Cisco IOS-XR template
			{
				Type:             DeviceTypeCisco,
				Model:            CiscoIOSXR,
				GetConfigCommand: "show running-config",
				GetConfigXPath:   "/device/configuration",
				DetectionPatterns: []string{
					"urn:ietf:params:netconf:capability:candidate",
					"http://cisco.com/ns/yang/Cisco-IOS-XR",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "show interfaces",
					"show version":        "show version",
					"show running-config": "show running-config",
				},
			},

			// Cisco IOS template
			{
				Type:             DeviceTypeCisco,
				Model:            CiscoIOS,
				GetConfigCommand: "show running-config",
				GetConfigXPath:   "/device/configuration",
				DetectionPatterns: []string{
					"http://cisco.com/ns/yang/ned/ios",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "show interfaces",
					"show version":        "show version",
					"show running-config": "show running-config",
				},
			},

			// Juniper Junos template
			{
				Type:             DeviceTypeJuniper,
				Model:            JuniperJunos,
				GetConfigCommand: "show configuration",
				GetConfigXPath:   "/configuration",
				DetectionPatterns: []string{
					"http://xml.juniper.net/xnm/1.1/xnm",
					"http://xml.juniper.net/junos",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "show interfaces",
					"show version":        "show version",
					"show running-config": "show configuration",
				},
			},

			// Arista EOS template
			{
				Type:             DeviceTypeArista,
				Model:            AristaEOS,
				GetConfigCommand: "show running-config",
				GetConfigXPath:   "/config",
				DetectionPatterns: []string{
					"http://openconfig.net/yang/interfaces",
					"http://arista.com/yang",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "show interfaces",
					"show version":        "show version",
					"show running-config": "show running-config",
				},
			},

			// Huawei VRP template
			{
				Type:             DeviceTypeHuawei,
				Model:            HuaweiVRP,
				GetConfigCommand: "display current-configuration",
				GetConfigXPath:   "/configuration",
				DetectionPatterns: []string{
					"http://www.huawei.com/netconf",
					"huawei-vrp",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "display interface",
					"show version":        "display version",
					"show running-config": "display current-configuration",
				},
			},

			// Generic template (fallback)
			{
				Type:             DeviceTypeGeneric,
				Model:            GenericModel,
				GetConfigCommand: "get-config",
				GetConfigXPath:   "/",
				DetectionPatterns: []string{
					"urn:ietf:params:netconf:base:1.0",
				},
				CommandMappings: map[string]string{
					"show interfaces":     "get-config interfaces",
					"show version":        "get-config system",
					"show running-config": "get-config",
				},
			},
		},
	}

	return registry
}

// DetectDeviceType detects the device type and model from capabilities
func (r *Registry) DetectDeviceType(capabilities string) (DeviceType, DeviceModel) {
	// Default to generic if no match is found
	deviceType := DeviceTypeGeneric
	deviceModel := GenericModel

	// Check each template's detection patterns
	for _, template := range r.templates {
		for _, pattern := range template.DetectionPatterns {
			if strings.Contains(capabilities, pattern) {
				return template.Type, template.Model
			}
		}
	}

	return deviceType, deviceModel
}

// GetTemplate returns the template for the specified device type and model
func (r *Registry) GetTemplate(deviceType DeviceType, deviceModel DeviceModel) (*Template, error) {
	// Look for an exact match first
	for _, template := range r.templates {
		if template.Type == deviceType && template.Model == deviceModel {
			return &template, nil
		}
	}

	// If no exact match, look for a match by type only
	for _, template := range r.templates {
		if template.Type == deviceType {
			return &template, nil
		}
	}

	// If no match by type, return the generic template
	for _, template := range r.templates {
		if template.Type == DeviceTypeGeneric {
			return &template, nil
		}
	}

	return nil, fmt.Errorf("no template found for device type %s and model %s", deviceType, deviceModel)
}

// GetCommandMapping returns the device-specific command for a generic command
func (t *Template) GetCommandMapping(genericCommand string) string {
	if command, ok := t.CommandMappings[genericCommand]; ok {
		return command
	}
	return genericCommand // Return the original command if no mapping is found
}

// DetectDeviceFromConfig attempts to detect the device type and model from a configuration
func (r *Registry) DetectDeviceFromConfig(config string) (DeviceType, DeviceModel) {
	// Default to generic if no match is found
	deviceType := DeviceTypeGeneric
	deviceModel := GenericModel

	// Check for Cisco IOS-XR
	if strings.Contains(config, "IOS XR") || strings.Contains(config, "ios-xr") {
		return DeviceTypeCisco, CiscoIOSXR
	}

	// Check for Cisco IOS
	if strings.Contains(config, "IOS Software") || strings.Contains(config, "ios-xe") {
		return DeviceTypeCisco, CiscoIOS
	}

	// Check for Cisco NX-OS
	if strings.Contains(config, "NX-OS") || strings.Contains(config, "nxos") {
		return DeviceTypeCisco, CiscoNXOS
	}

	// Check for Juniper Junos
	if strings.Contains(config, "JUNOS") || strings.Contains(config, "junos") {
		return DeviceTypeJuniper, JuniperJunos
	}

	// Check for Arista EOS
	if strings.Contains(config, "Arista") || strings.Contains(config, "EOS") {
		return DeviceTypeArista, AristaEOS
	}

	// Check for Huawei VRP
	if strings.Contains(config, "Huawei") || strings.Contains(config, "VRP") {
		return DeviceTypeHuawei, HuaweiVRP
	}

	return deviceType, deviceModel
}

// GetXMLNamespaces returns the XML namespaces for the device type
func (t *Template) GetXMLNamespaces() map[string]string {
	switch t.Type {
	case DeviceTypeCisco:
		switch t.Model {
		case CiscoIOSXR:
			return map[string]string{
				"ios-xr": "http://cisco.com/ns/yang/Cisco-IOS-XR",
			}
		case CiscoIOS:
			return map[string]string{
				"ios": "http://cisco.com/ns/yang/ned/ios",
			}
		case CiscoNXOS:
			return map[string]string{
				"nxos": "http://cisco.com/ns/yang/cisco-nx-os",
			}
		}
	case DeviceTypeJuniper:
		return map[string]string{
			"junos": "http://xml.juniper.net/junos/*/junos",
		}
	case DeviceTypeArista:
		return map[string]string{
			"eos": "http://arista.com/yang/openconfig",
		}
	case DeviceTypeHuawei:
		return map[string]string{
			"vrp": "http://www.huawei.com/netconf/vrp",
		}
	}

	// Default namespaces
	return map[string]string{
		"nc": "urn:ietf:params:xml:ns:netconf:base:1.0",
	}
}
