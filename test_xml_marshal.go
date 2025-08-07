package main

import (
	"encoding/xml"
	"fmt"
)

type TestStruct struct {
	XMLName xml.Name `xml:"test"`
	Value   string   `xml:"value"`
}

func main() {
	test := TestStruct{Value: "test value"}

	// Test with MarshalIndent
	xmlData, err := xml.MarshalIndent(test, "", "  ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("Output from xml.MarshalIndent:")
	fmt.Println(string(xmlData))

	// Check if it starts with XML declaration
	if len(xmlData) > 5 && string(xmlData[:5]) == "<?xml" {
		fmt.Println("xml.MarshalIndent DOES include XML declaration")
	} else {
		fmt.Println("xml.MarshalIndent does NOT include XML declaration")
	}
}
