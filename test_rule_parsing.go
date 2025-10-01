package main

import (
	"fmt"
	"log"

	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
)

func main() {
	fmt.Println("🔍 Testing go-libaudit rule parsing capabilities")
	fmt.Println("================================================")

	// Test different types of audit rules
	testRules := []string{
		"-w /etc/passwd -p wa -k identity",
		"-w /etc/shadow -p wa -k identity",
		"-a always,exit -F arch=b64 -S execve -k exec",
		"-a always,exit -F arch=b32 -S open,openat -k file_access",
	}

	for i, ruleStr := range testRules {
		fmt.Printf("\n📋 Test Rule %d: %s\n", i+1, ruleStr)

		// Parse the raw rule string into structured representation
		parsedRule, err := flags.Parse(ruleStr)
		if err != nil {
			log.Printf("❌ Failed to parse rule: %v", err)
			continue
		}

		fmt.Printf("✅ Successfully parsed rule\n")
		fmt.Printf("   Type: %T\n", parsedRule)
		fmt.Printf("   Rule Type: %v\n", parsedRule.TypeOf())

		// Convert to wire format (what gets sent to kernel)
		wireFormat, err := rule.Build(parsedRule)
		if err != nil {
			log.Printf("❌ Failed to build wire format: %v", err)
			continue
		}

		fmt.Printf("✅ Successfully built wire format (%d bytes)\n", len(wireFormat))

		// Convert back to command line representation
		cmdLine, err := rule.ToCommandLine(wireFormat, true)
		if err != nil {
			log.Printf("⚠️  Could not convert back to command line: %v", err)
		} else {
			fmt.Printf("🔄 Round-trip result: %s\n", cmdLine)
		}
	}

	fmt.Println("\n✅ Rule parsing test completed!")
}
