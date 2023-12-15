```markdown
# ThePacketCollector

ThePacketCollector is a Go application designed to collect network traffic on a specified interface and send it to a Graylog syslog server. It also includes an internal HTTP server for monitoring and logging.

## Prerequisites

- Go version 1.20.10 or later (installed via gvm)
- Additional Go modules: `github.com/google/gopacket` and `gopkg.in/yaml.v2`
- Graylog syslog server for receiving network traffic logs

## Installation

### 1. Install Go with gvm

If you don't have Go installed, you can use the Go Version Manager (gvm) to install and manage different Go versions.

```bash
# Install gvm
bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)

# Load gvm script
source ~/.gvm/scripts/gvm

# Install Go version 1.20.10
gvm install go1.20.10
gvm use go1.20.10 --default
```

### 2. Clone the Repository

```bash
git clone https://github.com/davestj/ThePacketCollector.git
cd ThePacketCollector
```

### 3. Generate Self-Signed SSL Certificate and Key

Before running the application, generate a self-signed SSL certificate and key. The script will automatically extract the system's IP address as the Common Name (CN) for the certificate.

```bash
./generate_cert.sh
```

### 4. Install Required Go Modules

```bash
go get -u github.com/google/gopacket
go get -u gopkg.in/yaml.v2
```

### 5. Build the Application

```bash
go build -o ThePacketCollector
```

## Configuration

Modify the `config.yaml` file to specify the network interface, Graylog syslog server details, and other configuration options.

```yaml
interface: "eth0"
snaplen: 65535
promiscuous: true
timeout: 30s
syslog:
  server: "127.0.0.1"
  port: 514
httpPort: 3000
certFile: "server.crt"
keyFile: "server.key"
```

## Usage

Run the compiled binary to start collecting network traffic and serving the internal HTTP server, as root user.

```bash
sudo ./ThePacketCollector
```

## Scenarios

- Monitor network traffic on a specific interface for security analysis.
- Send network traffic logs to a Graylog syslog server for centralized logging.
- Use the internal HTTP server to check the status of the application and view recent log entries.


```
