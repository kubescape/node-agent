# Network Neighborhood CEL Functions

This package provides CEL (Common Expression Language) functions for querying network neighborhood profiles. These functions allow you to check if specific network addresses or domains were used by containers based on their network neighborhood profiles.

## Available Functions

### Address Functions

#### `nn.was_address_in_egress(containerID, address)`
Checks if a specific IP address was used in egress traffic by the container.

**Parameters:**
- `containerID` (string): The container ID
- `address` (string): The IP address to check

**Returns:** `bool` - `true` if the address was used in egress traffic, `false` otherwise

**Example:**
```cel
nn.was_address_in_egress("container-123", "192.168.1.100")
```

#### `nn.was_address_in_ingress(containerID, address)`
Checks if a specific IP address was used in ingress traffic by the container.

**Parameters:**
- `containerID` (string): The container ID
- `address` (string): The IP address to check

**Returns:** `bool` - `true` if the address was used in ingress traffic, `false` otherwise

**Example:**
```cel
nn.was_address_in_ingress("container-123", "172.16.0.10")
```

### Domain Functions

#### `nn.is_domain_in_egress(containerID, domain)`
Checks if a specific domain was used in egress traffic by the container.

**Parameters:**
- `containerID` (string): The container ID
- `domain` (string): The domain name to check

**Returns:** `bool` - `true` if the domain was used in egress traffic, `false` otherwise

**Example:**
```cel
nn.is_domain_in_egress("container-123", "api.example.com")
```

#### `nn.is_domain_in_ingress(containerID, domain)`
Checks if a specific domain was used in ingress traffic by the container.

**Parameters:**
- `containerID` (string): The container ID
- `domain` (string): The domain name to check

**Returns:** `bool` - `true` if the domain was used in ingress traffic, `false` otherwise

**Example:**
```cel
nn.is_domain_in_ingress("container-123", "loadbalancer.example.com")
```

## Usage Examples

### Basic Network Monitoring
```cel
// Check if container communicated with external services
nn.was_address_in_egress("container-123", "8.8.8.8") ||
nn.is_domain_in_egress("container-123", "dns.google.com")
```

### Security Monitoring
```cel
// Check if container communicated with suspicious addresses
nn.was_address_in_egress("container-123", "192.168.1.100") &&
nn.is_domain_in_egress("container-123", "malicious.com")
```

### Load Balancer Monitoring
```cel
// Check if container received traffic from load balancer
nn.was_address_in_ingress("container-123", "172.16.0.10") &&
nn.is_domain_in_ingress("container-123", "loadbalancer.example.com")
```

### Complex Network Rules
```cel
// Check for suspicious network patterns
(nn.was_address_in_egress("container-123", "10.0.0.50") && 
 nn.is_domain_in_egress("container-123", "database.internal")) ||
(nn.was_address_in_egress("container-123", "192.168.1.100") && 
 nn.is_domain_in_egress("container-123", "api.example.com"))
```

### External Communication Monitoring
```cel
// Monitor external DNS queries
nn.was_address_in_egress("container-123", "8.8.8.8") &&
nn.is_domain_in_egress("container-123", "dns.google.com")
```

### Internal Service Communication
```cel
// Monitor internal service communication
nn.was_address_in_egress("container-123", "10.0.0.50") &&
nn.is_domain_in_egress("container-123", "database.internal")
```

## Network Neighborhood Structure

The network neighborhood profile contains information about:

- **Egress Traffic**: Outbound network connections from the container
- **Ingress Traffic**: Inbound network connections to the container
- **IP Addresses**: Direct IP address communication
- **DNS Names**: Domain name resolution and communication
- **Ports**: Network ports used for communication
- **Protocols**: Network protocols (TCP, UDP, etc.)

## Notes

- All functions return `false` if no network neighborhood profile is available for the container
- Functions are case-sensitive for domain name matching
- The functions use the container's network neighborhood profile data to determine if network operations were performed
- IP addresses should be in standard format (e.g., "192.168.1.100", "::1")
- Domain names should be in standard format (e.g., "example.com", "api.internal")
- Multiple DNS names can be associated with a single IP address
- The functions check both direct IP address communication and domain name resolution 