package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	sigsyaml "sigs.k8s.io/yaml"
)

var (
	inputFile  string
	outputFile string
	keyFile    string
	objectType string
	useKeyless bool
	verbose    bool
	strict     bool
	jsonOutput bool
	publicOnly bool
	command    string
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command = os.Args[1]

	argsRewritten := false
	if command == "-h" || command == "--help" {
		printUsage()
		os.Exit(0)
	}
	if strings.HasPrefix(command, "-") {
		command = "sign"
		argsRewritten = true
	}

	switch command {
	case "sign", "":
		parseSignFlags()
		if argsRewritten {
			os.Args = append([]string{"sign-object"}, os.Args[1:]...)
		}
	case "verify":
		parseVerifyFlags()
		os.Args = append([]string{"sign-object verify"}, os.Args[2:]...)
	case "generate-keypair":
		parseGenerateFlags()
		os.Args = append([]string{"sign-object generate-keypair"}, os.Args[2:]...)
	case "extract-signature":
		parseExtractFlags()
		os.Args = append([]string{"sign-object extract-signature"}, os.Args[2:]...)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if err := runCommand(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseSignFlags() {
	fs := flag.NewFlagSet("sign-object sign", flag.ExitOnError)
	fs.StringVar(&inputFile, "file", "", "Input object YAML file (required)")
	fs.StringVar(&outputFile, "output", "", "Output file for signed object (required)")
	fs.StringVar(&keyFile, "key", "", "Path to private key file")
	fs.StringVar(&objectType, "type", "auto", "Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto")
	fs.BoolVar(&useKeyless, "keyless", false, "Use keyless signing (OIDC)")
	fs.BoolVar(&verbose, "verbose", false, "Enable verbose logging")

	offset := 2
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-") {
		offset = 1
	}

	if err := fs.Parse(os.Args[offset:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if outputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --output is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if !useKeyless && keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: either --keyless or --key must be specified")
		fs.PrintDefaults()
		os.Exit(1)
	}
}

func parseVerifyFlags() {
	fs := flag.NewFlagSet("sign-object verify", flag.ExitOnError)
	fs.StringVar(&inputFile, "file", "", "Signed object YAML file (required)")
	fs.StringVar(&objectType, "type", "auto", "Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto")
	fs.BoolVar(&strict, "strict", true, "Require trusted issuer/identity")
	fs.BoolVar(&verbose, "verbose", false, "Enable verbose logging")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
}

func parseGenerateFlags() {
	fs := flag.NewFlagSet("sign-object generate-keypair", flag.ExitOnError)
	fs.StringVar(&outputFile, "output", "", "Output PEM file")
	fs.BoolVar(&publicOnly, "public-only", false, "Only output public key")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if outputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --output is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
}

func parseExtractFlags() {
	fs := flag.NewFlagSet("sign-object extract-signature", flag.ExitOnError)
	fs.StringVar(&inputFile, "file", "", "Signed object YAML file (required)")
	fs.StringVar(&objectType, "type", "auto", "Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto")
	fs.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
}

func runCommand() error {
	switch command {
	case "sign", "":
		return runSign()
	case "verify":
		return runVerify()
	case "generate-keypair":
		return runGenerateKeyPair()
	case "extract-signature":
		return runExtractSignature()
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func runSign() error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	if verbose {
		fmt.Printf("Reading profile from: %s\n", inputFile)
		fmt.Printf("Profile size: %d bytes\n", len(data))
	}

	profileAdapter, err := detectObjectType(objectType, data)
	if err != nil {
		return fmt.Errorf("failed to detect profile type: %w", err)
	}

	if verbose {
		fmt.Printf("Detected object type: %s\n", getObjectName(profileAdapter))
	}

	var signErr error
	if useKeyless {
		if verbose {
			fmt.Println("Using keyless signing (OIDC)")
		}
		signErr = signature.SignObjectKeyless(profileAdapter)
	} else {
		if verbose {
			fmt.Printf("Using local key from: %s\n", keyFile)
		}

		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from key file")
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}

		signErr = signature.SignObject(profileAdapter, signature.WithPrivateKey(privateKey))
	}

	if signErr != nil {
		return fmt.Errorf("failed to sign profile: %w", signErr)
	}

	sig, err := signature.GetObjectSignature(profileAdapter)
	if err != nil {
		return fmt.Errorf("failed to get signature: %w", err)
	}

	fmt.Printf("✓ Profile signed successfully\n")
	fmt.Printf("  Issuer: %s\n", sig.Issuer)
	fmt.Printf("  Identity: %s\n", sig.Identity)
	fmt.Printf("  Timestamp: %d\n", sig.Timestamp)

	profileBytes, err := sigsyaml.Marshal(profileAdapter.GetUpdatedObject())
	if err != nil {
		return fmt.Errorf("failed to marshal signed object: %w", err)
	}

	if err := os.WriteFile(outputFile, profileBytes, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("✓ Signed profile written to: %s\n", outputFile)
	return nil
}

func runVerify() error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if verbose {
		fmt.Printf("Reading profile from: %s\n", inputFile)
	}

	profileAdapter, err := detectObjectType(objectType, data)
	if err != nil {
		return fmt.Errorf("failed to detect profile type: %w", err)
	}

	sig, err := signature.GetObjectSignature(profileAdapter)
	if err != nil {
		return fmt.Errorf("profile is not signed: %w", err)
	}

	fmt.Printf("Signature found:\n")
	fmt.Printf("  Issuer: %s\n", sig.Issuer)
	fmt.Printf("  Identity: %s\n", sig.Identity)
	fmt.Printf("  Timestamp: %d\n", sig.Timestamp)

	var verifyErr error
	if strict {
		if verbose {
			fmt.Println("Verifying with strict mode (keyless signatures must have issuer/identity)")
		}
		verifyErr = signature.VerifyObjectStrict(profileAdapter)
	} else {
		if verbose {
			fmt.Println("Verifying in non-strict mode (allowing untrusted signatures)")
		}
		verifyErr = signature.VerifyObjectAllowUntrusted(profileAdapter)
	}

	if verifyErr != nil {
		return fmt.Errorf("signature verification failed: %w", verifyErr)
	}

	fmt.Printf("✓ Signature verification successful\n")
	return nil
}

func runGenerateKeyPair() error {
	adapter, err := signature.NewCosignAdapter(false)
	if err != nil {
		return fmt.Errorf("failed to create adapter: %w", err)
	}

	pubKeyBytes, err := adapter.GetPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	if publicOnly {
		if err := os.WriteFile(outputFile, pubKeyBytes, 0644); err != nil {
			return fmt.Errorf("failed to write public key file: %w", err)
		}

		fmt.Printf("✓ Public key written to: %s\n", outputFile)
		return nil
	}

	privKeyBytes, err := adapter.GetPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}

	if err := os.WriteFile(outputFile, privKeyBytes, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	pubKeyFile := outputFile + ".pub"
	if err := os.WriteFile(pubKeyFile, pubKeyBytes, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	fmt.Printf("✓ Private key written to: %s\n", outputFile)
	fmt.Printf("✓ Public key written to: %s\n", pubKeyFile)
	return nil
}

func runExtractSignature() error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	profileAdapter, err := detectObjectType(objectType, data)
	if err != nil {
		return fmt.Errorf("failed to detect profile type: %w", err)
	}

	sig, err := signature.GetObjectSignature(profileAdapter)
	if err != nil {
		return fmt.Errorf("profile is not signed: %w", err)
	}

	sigInfo := map[string]interface{}{
		"signature_size":     len(sig.Signature),
		"certificate_size":   len(sig.Certificate),
		"issuer":             sig.Issuer,
		"identity":           sig.Identity,
		"timestamp":          sig.Timestamp,
		"signature_base64":   base64.StdEncoding.EncodeToString(sig.Signature),
		"certificate_base64": base64.StdEncoding.EncodeToString(sig.Certificate),
	}

	if jsonOutput {
		jsonData, err := json.MarshalIndent(sigInfo, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Println("Signature Information:")
		fmt.Printf("  Issuer: %s\n", sig.Issuer)
		fmt.Printf("  Identity: %s\n", sig.Identity)
		fmt.Printf("  Timestamp: %d\n", sig.Timestamp)
		fmt.Printf("  Signature Size: %d bytes\n", len(sig.Signature))
		fmt.Printf("  Certificate Size: %d bytes\n", len(sig.Certificate))

		block, _ := pem.Decode(sig.Certificate)
		if block != nil {
			fmt.Printf("  Certificate Type: %s\n", block.Type)
		}
	}

	return nil
}

func detectObjectType(objectType string, data []byte) (signature.SignableObject, error) {
	var decoded map[string]interface{}
	if err := k8syaml.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	kind, _ := decoded["kind"].(string)
	apiVersion, _ := decoded["apiVersion"].(string)

	if verbose {
		fmt.Printf("Detected API: %s, Kind: %s\n", apiVersion, kind)
	}

	if objectType != "auto" {
		switch strings.ToLower(objectType) {
		case "applicationprofile", "application-profile", "ap":
			return loadApplicationProfile(data)
		case "seccompprofile", "seccomp-profile", "sp":
			return loadSeccompProfile(data)
		case "networkneighborhood", "network-neighborhood", "nn":
			return loadNetworkNeighborhood(data)
		case "rules", "rule", "r":
			return loadRules(data)
		default:
			return nil, fmt.Errorf("unknown object type: %s", objectType)
		}
	}

	if strings.Contains(strings.ToLower(apiVersion), "softwarecomposition") {
		switch strings.ToLower(kind) {
		case "applicationprofile", "application-profile":
			return loadApplicationProfile(data)
		case "seccompprofile", "seccomp-profile":
			return loadSeccompProfile(data)
		case "networkneighborhood", "network-neighborhood":
			return loadNetworkNeighborhood(data)
		}
	}

	if strings.Contains(strings.ToLower(apiVersion), "kubescape.io") && strings.ToLower(kind) == "rules" {
		return loadRules(data)
	}

	return nil, fmt.Errorf("unable to auto-detect object type")
}

func loadApplicationProfile(data []byte) (signature.SignableObject, error) {
	var profile v1beta1.ApplicationProfile
	if err := k8syaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ApplicationProfile: %w", err)
	}
	return profiles.NewApplicationProfileAdapter(&profile), nil
}

func loadSeccompProfile(data []byte) (signature.SignableObject, error) {
	var profile v1beta1.SeccompProfile
	if err := k8syaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SeccompProfile: %w", err)
	}
	return profiles.NewSeccompProfileAdapter(&profile), nil
}

func loadNetworkNeighborhood(data []byte) (signature.SignableObject, error) {
	var nn v1beta1.NetworkNeighborhood
	if err := k8syaml.Unmarshal(data, &nn); err != nil {
		return nil, fmt.Errorf("failed to unmarshal NetworkNeighborhood: %w", err)
	}
	return profiles.NewNetworkNeighborhoodAdapter(&nn), nil
}

func loadRules(data []byte) (signature.SignableObject, error) {
	var rules rulemanagertypesv1.Rules
	if err := k8syaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Rules: %w", err)
	}
	return profiles.NewRulesAdapter(&rules), nil
}

func getObjectName(profile signature.SignableObject) string {
	if _, ok := profile.(*profiles.ApplicationProfileAdapter); ok {
		return "ApplicationProfile"
	}
	if _, ok := profile.(*profiles.SeccompProfileAdapter); ok {
		return "SeccompProfile"
	}
	if _, ok := profile.(*profiles.NetworkNeighborhoodAdapter); ok {
		return "NetworkNeighborhood"
	}
	if _, ok := profile.(*profiles.RulesAdapter); ok {
		return "Rules"
	}
	return "Unknown"
}

func printUsage() {
	fmt.Println(`sign-object - Sign and verify Kubernetes security objects

USAGE:
    sign-object <command> [flags]

COMMANDS:
    sign              Sign a profile (default command)
    verify            Verify a signed object
    generate-keypair  Generate a new ECDSA key pair
    extract-signature Extract signature info from a profile
    help              Show this help message

SIGN FLAGS:
    --file <path>           Input object YAML file (required)
    --output <path>         Output file for signed object (required)
    --keyless               Use keyless signing (OIDC)
    --key <path>            Path to private key file
    --type <type>           Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto (default: auto)
    --verbose               Enable verbose logging

VERIFY FLAGS:
    --file <path>                 Signed object YAML file (required)
    --type <type>                 Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto (default: auto)
    --strict                      Require trusted issuer/identity (default: true)
    --verbose                     Enable verbose logging

GENERATE-KEYPAIR FLAGS:
    --output <path>         Output PEM file for private key (required)
    --public-only           Only output public key (no private key)

EXTRACT-SIGNATURE FLAGS:
    --file <path>                 Signed object YAML file (required)
    --type <type>                 Object type: applicationprofile, seccompprofile, networkneighborhood, rules, or auto (default: auto)
    --json                        Output as JSON

EXAMPLES:
    # Sign with keyless (OIDC)
    sign-object --keyless --file object.yaml --output signed-object.yaml

    # Sign with local key
    sign-object --key my-key.pem --file object.yaml --output signed-object.yaml

    # Verify a signed object
    sign-object verify --file signed-object.yaml

    # Generate a key pair (writes my-key.pem and my-key.pem.pub)
    sign-object generate-keypair --output my-key.pem

    # Generate only public key
    sign-object generate-keypair --output my-key.pem --public-only

    # Extract signature information
    sign-object extract-signature --file signed-object.yaml

For more information, see: docs/signing/README.md`)
}
