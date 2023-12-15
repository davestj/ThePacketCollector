package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v2"
)

// Configuration struct to hold the configuration options
type Config struct {
	Interface   string        `yaml:"interface"`
	Snaplen     int           `yaml:"snaplen"`
	Promiscuous bool          `yaml:"promiscuous"`
	Timeout     time.Duration `yaml:"timeout"`
	Syslog      struct {
		Server string `yaml:"server"`
		Port   int    `yaml:"port"`
	} `yaml:"syslog"`
	HttpPort int    `yaml:"httpPort"`
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

var config Config
var logMessages []string

func main() {
	// Check if the user is root or daemon, exit if not
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal("Error determining current user:", err)
	}

	if currentUser.Username != "root" && currentUser.Username != "daemon" {
		log.Fatal("The application must be run as root or daemon user.")
		os.Exit(1) // Exit with a non-zero status
	}
	// Read configuration from YAML file
	if err := readConfig("config.yaml", &config); err != nil {
		log.Fatal("Error reading configuration:", err)
	}

	// Start internal HTTP server
	go startHTTPServer()

	// Start packet collector
	handle, err := pcap.OpenLive(config.Interface, int32(config.Snaplen), config.Promiscuous, config.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		go sendToSyslog(packet, config.Syslog.Server, config.Syslog.Port)
	}
}

func startHTTPServer() {
	serverAddr := fmt.Sprintf(":%d", config.HttpPort)
	log.Printf("HTTP server started on %s\n", serverAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/logs", handleLogs)
	mux.HandleFunc("/syslog-status", handleSyslogStatus)

	server := &http.Server{
		Addr:         serverAddr,
		Handler:      loggingMiddleware(mux), // Apply logging middleware
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := server.ListenAndServeTLS(config.CertFile, config.KeyFile)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal("HTTP server error: ", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)

		// Limit request size to 1 MB
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		// Set HTTP Strict Transport Security
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Set Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")

		// Continue with the next handler
		next.ServeHTTP(w, r)
	})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	// Display the last 30 log messages
	count := len(logMessages)
	startIndex := 0
	if count > 30 {
		startIndex = count - 30
	}

	for i := startIndex; i < count; i++ {
		fmt.Fprintln(w, logMessages[i])
	}
}

func handleSyslogStatus(w http.ResponseWriter, r *http.Request) {
	// Display information about syslog server, port, and captured interface
	syslogInfo := fmt.Sprintf("Syslog Server: %s, Port: %d\n", config.Syslog.Server, config.Syslog.Port)
	interfaceInfo := fmt.Sprintf("Captured Interface: %s\n", config.Interface)

	// Combine the information and respond
	statusInfo := syslogInfo + interfaceInfo
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(statusInfo))
}

func sendToSyslog(packet gopacket.Packet, syslogServer string, syslogPort int) {
	// Convert the packet to a string representation
	packetDetails := packet.String()

	// Prepare the raw log message with packet details
	logMessage := fmt.Sprintf(
		"Raw Packet Details: %s",
		packetDetails,
	)

	// Send the raw log message to syslog
	err := sendToSyslogServer(logMessage, syslogServer, syslogPort)
	if err != nil {
		log.Println("Error sending message to syslog:", err)
	} else {
		log.Println("Packet sent to syslog successfully")
	}

	// Store the log message in the slice
	logMessages = append(logMessages, logMessage)
}

func sendToSyslogServer(message string, syslogServer string, syslogPort int) error {
	// Establish a connection to the syslog server
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", syslogServer, syslogPort))
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send the log message to the syslog server
	_, err = fmt.Fprintf(conn, "%s\n", message)
	if err != nil {
		return err
	}

	return nil
}

func readConfig(filename string, config *Config) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return err
	}

	return nil
}

