# Path Traversal Demo Setup Script
# Run this to create all necessary files

Write-Host "🔧 Setting up Path Traversal Demo..." -ForegroundColor Cyan
Write-Host ""

# Create workspace directory
Write-Host "Creating workspace directory..." -ForegroundColor Yellow
New-Item -Path "C:\Tools\mcp_test" -ItemType Directory -Force | Out-Null

# Create legitimate workspace files
Write-Host "Creating legitimate workspace files..." -ForegroundColor Yellow

@"
{
  "app_name": "SecureApp",
  "version": "1.0.0",
  "database": "localhost:5432",
  "environment": "production",
  "api_endpoint": "https://api.secureapp.com"
}
"@ | Out-File "C:\Tools\mcp_test\config.txt" -Encoding UTF8

@"
Asset_ID,Name,Value,Owner
001,Server-A,5000,IT-Department
002,Laptop-X,1500,Engineering
003,Database-1,10000,Operations
004,Storage-Y,3000,Data-Team
"@ | Out-File "C:\Tools\mcp_test\assets.csv" -Encoding UTF8

@"
# SecureApp Project

## Overview
This is the main project workspace for SecureApp.

## Directory Structure
- config.txt: Application configuration
- assets.csv: Asset inventory data

## Getting Started
Run the application with the configuration file.
"@ | Out-File "C:\Tools\mcp_test\README.md" -Encoding UTF8

Write-Host "✅ Workspace files created in C:\Tools\mcp_test" -ForegroundColor Green

# Create secrets directory
Write-Host ""
Write-Host "Creating sensitive files (attack targets)..." -ForegroundColor Yellow
New-Item -Path "C:\secrets" -ItemType Directory -Force | Out-Null

@"
# PRODUCTION CREDENTIALS - HIGHLY SENSITIVE!
# DO NOT SHARE OR COMMIT TO VERSION CONTROL

database_password=Pr0d_DB_P@ssw0rd_2025!
api_key=sk-prod-abc123xyz789def456ghi
admin_token=admin_secret_token_production_2025
stripe_secret_key=sk_live_51234567890abcdefghij
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
jwt_secret=super_secret_jwt_key_for_production_use_only
encryption_key=AES256_ENCRYPTION_KEY_BASE64_ENCODED_HERE

# Database Connections
prod_db_host=prod-db-cluster.company.internal
prod_db_port=5432
prod_db_name=production_database
prod_db_user=admin
prod_db_password=Adm1n_DB_P@ss_Secure!

# External Services
sendgrid_api_key=SG.xxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyy
twilio_auth_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
slack_webhook=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX

# OAuth Credentials  
oauth_client_id=123456789012-xxxxxxxxxxxxxxxx.apps.googleusercontent.com
oauth_client_secret=GOCSPX-xxxxxxxxxxxxxxxxxxxxx
"@ | Out-File "C:\secrets\credentials.txt" -Encoding UTF8

Write-Host "✅ Sensitive files created in C:\secrets" -ForegroundColor Green

# Create fake SSH directory and key
Write-Host ""
Write-Host "Creating fake SSH key..." -ForegroundColor Yellow
$sshDir = "C:\Users\$env:USERNAME\.ssh"
New-Item -Path $sshDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

@"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvKqxr8LsJHxBQqCcPqPxZmW8tLmRBKZlqOuCqvqgWGwAAAJhqPaJWaj2i
VgAAAAtzc2gtZWQyNTUxOQAAACBvKqxr8LsJHxBQqCcPqPxZmW8tLmRBKZlqOuCqvqgWGw
AAAED4i8MFxBP8qxI1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
-----END OPENSSH PRIVATE KEY-----

⚠️ THIS IS A FAKE KEY FOR DEMONSTRATION PURPOSES
⚠️ In a real attack, this would be an actual SSH private key
⚠️ An attacker with this key could access any server it's authorized for
⚠️ This demonstrates the severity of path traversal vulnerabilities
"@ | Out-File "$sshDir\id_rsa" -Encoding UTF8

Write-Host "✅ Fake SSH key created in $sshDir" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✅ SETUP COMPLETE!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "📁 Files created:" -ForegroundColor Yellow
Write-Host "  • C:\Tools\mcp_test\config.txt" -ForegroundColor White
Write-Host "  • C:\Tools\mcp_test\assets.csv" -ForegroundColor White
Write-Host "  • C:\Tools\mcp_test\README.md" -ForegroundColor White
Write-Host "  • C:\secrets\credentials.txt (SENSITIVE)" -ForegroundColor Red
Write-Host "  • $sshDir\id_rsa (FAKE SSH KEY)" -ForegroundColor Red
Write-Host ""
Write-Host "🚀 Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run: npx @modelcontextprotocol/inspector python vuln_mcp_path_traversal_FIXED.py"
Write-Host "  2. Open browser to: http://localhost:5173"
Write-Host "  3. Start exploiting!"
Write-Host ""
Write-Host "🎯 Attack URIs to try:" -ForegroundColor Yellow
Write-Host "  • file:///C:/tools/mcp_test/../secrets/credentials.txt"
Write-Host "  • file:///C:/tools/mcp_test/../../Users/$env:USERNAME/.ssh/id_rsa"
Write-Host "  • file:///C:/tools/mcp_test/../../Windows/System32/drivers/etc/hosts"
Write-Host ""