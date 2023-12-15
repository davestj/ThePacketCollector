#!/bin/bash

# Get the system's IP address
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Set the certificate and key file paths
CERT_FILE="server.crt"
KEY_FILE="server.key"

# Generate a self-signed SSL certificate and key
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=$IP_ADDRESS"

# Provide feedback
echo "Self-signed SSL certificate and key generated successfully."
echo "Certificate file: $CERT_FILE"
echo "Key file: $KEY_FILE"

