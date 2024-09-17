#!/bin/bash

# Check if the script received an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <Box Name>"
    exit 1
fi

# Check if directory already exists
if [ -d "$1" ]; then
    echo "Directory $1 already exists. Exiting."
    exit 1
fi

# Generate the directory structure
mkdir "$1"
cd "$1"
mkdir enumeration attachments artifacts

# Create the README.md template
cat <<EOF >"README.md"
# $1

## Network Enumeration

### TCP Scan

\`\`\`bash
sudo rustscan -a \$IP -r 0-65535 -- -A -Pn -oN enumeration/tcp.all.nmap
\`\`\`

## Web Enumeration

### Vhost Discovery

### Walking an Application

### Web Content Discovery

## Foothold

## PrivEsc

EOF

cd ..
echo "Created the following directory structure:"
tree "$1"
