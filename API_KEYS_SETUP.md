# API Keys and Environment Configuration Guide

## Overview

ThreatOps Free uses several external APIs for threat intelligence enrichment and alert notifications. This guide will help you configure all required API keys and environment variables.

## Required API Keys

### 1. VirusTotal API Key

**Purpose:** File, IP, and domain reputation checking  
**Free Tier:** 4 requests per minute  
**Get it here:** https://www.virustotal.com/gui/join-us

**Steps:**
1. Create a free account on VirusTotal
2. Navigate to your profile settings
3. Copy your API key
4. Set environment variable: `VIRUSTOTAL_API_KEY=your_key_here`

### 2. AbuseIPDB API Key

**Purpose:** IP reputation and abuse confidence scoring  
**Free Tier:** 1,000 requests per day  
**Get it here:** https://www.abuseipdb.com/register

**Steps:**
1. Create a free account on AbuseIPDB
2. Go to API section in your account
3. Generate an API key
4. Set environment variable: `ABUSEIPDB_API_KEY=your_key_here`

### 3. AlienVault OTX API Key

**Purpose:** Open Threat Exchange threat intelligence  
**Free Tier:** Unlimited (with rate limits)  
**Get it here:** https://otx.alienvault.com/

**Steps:**
1. Create a free account on AlienVault OTX
2. Go to Settings → API Integration
3. Copy your OTX Key
4. Set environment variable: `OTX_API_KEY=your_key_here`

## Email Notification Setup

### Gmail Configuration

For Gmail, you need to use an App Password (not your regular password):

**Steps:**
1. Enable 2-Step Verification on your Google Account
2. Go to: https://myaccount.google.com/apppasswords
3. Generate an app password for "Mail"
4. Use these settings:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
EMAIL_RECIPIENTS=security@company.com,soc@company.com
```

### Other Email Providers

**Microsoft Outlook/Office 365:**
```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
```

**Yahoo Mail:**
```bash
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
```

**Custom SMTP Server:**
```bash
SMTP_HOST=your.smtp.server
SMTP_PORT=587
SMTP_USER=your_username
SMTP_PASSWORD=your_password
```

## Slack Integration

### Webhook Setup

**Steps:**
1. Go to https://api.slack.com/messaging/webhooks
2. Create a new Slack app or use existing
3. Enable Incoming Webhooks
4. Add webhook to your workspace
5. Copy the Webhook URL

**Configuration:**
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Custom Webhook

For integration with other systems (PagerDuty, ServiceNow, etc.):

```bash
CUSTOM_WEBHOOK_URL=https://your-system.com/api/alerts
```

The webhook will receive POST requests with this payload:
```json
{
  "event_type": "security_alert",
  "severity": "High",
  "alert": {
    "id": "alert_id",
    "rule_name": "Alert Name",
    "host": "hostname",
    "ip": "192.168.1.1",
    "timestamp": "2024-01-01T10:00:00Z",
    ...
  }
}
```

## Response Automation Settings

**⚠️ WARNING:** Automated response features can affect production systems. Test thoroughly before enabling!

```bash
# Enable/disable automated responses
AUTO_RESPONSE_ENABLED=false

# Automatically block malicious IPs via firewall
AUTO_BLOCK_IPS=false

# Automatically disable compromised user accounts
AUTO_DISABLE_ACCOUNTS=false

# Automatically quarantine infected hosts
AUTO_QUARANTINE_FILES=false
```

**Permissions Required:**
- **Windows:** Administrator privileges for firewall and user management
- **Linux:** Root/sudo access for iptables and user management

## Environment Variable Setup

### Method 1: Create .env file (Recommended)

Create a file named `.env` in the project root:

```bash
# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here

# Email Notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_RECIPIENTS=security@company.com

# Slack Webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Response Automation (USE WITH CAUTION!)
AUTO_RESPONSE_ENABLED=false
AUTO_BLOCK_IPS=false
AUTO_DISABLE_ACCOUNTS=false
```

### Method 2: System Environment Variables

**Windows (PowerShell):**
```powershell
$env:VIRUSTOTAL_API_KEY="your_key_here"
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:OTX_API_KEY="your_key_here"
```

**Linux/macOS:**
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"
```

### Method 3: Configuration Wizard

Run the interactive setup wizard:

```bash
python -c "from config.settings import Settings; Settings().setup_wizard()"
```

## Testing Configuration

Test your API keys:

```bash
python -c "from config.settings import Settings; s = Settings(); print(s.validate_api_keys())"
```

Expected output:
```python
{
    'virustotal': True,
    'abuseipdb': True,
    'otx': True
}
```

## Security Best Practices

1. **Never commit API keys to version control**
   - Add `.env` to your `.gitignore`
   - Use environment variables or secret managers

2. **Rotate API keys regularly**
   - Set calendar reminders
   - Update keys every 90 days

3. **Use read-only API keys when possible**
   - Limit API key permissions
   - Create separate keys for different environments

4. **Monitor API usage**
   - Check API dashboards regularly
   - Set up usage alerts

5. **Secure your .env file**
   ```bash
   chmod 600 .env  # Linux/macOS only
   ```

6. **Use dedicated email accounts**
   - Create security@company.com for SOC alerts
   - Don't use personal email accounts

7. **Test webhooks in development first**
   - Use webhook testing tools
   - Verify payload format

## Troubleshooting

### Issue: "API key not configured" warning

**Solution:** Check that your environment variables are set:
```bash
python -c "import os; print(os.getenv('VIRUSTOTAL_API_KEY'))"
```

### Issue: Email alerts not working

**Solutions:**
- Verify SMTP credentials
- Check if 2FA is enabled (use app password)
- Ensure port 587 is not blocked
- Check spam folder

### Issue: Slack alerts not appearing

**Solutions:**
- Verify webhook URL is correct
- Check Slack app permissions
- Test webhook with curl:
  ```bash
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Test message"}' \
    YOUR_WEBHOOK_URL
  ```

### Issue: Rate limit exceeded

**Solutions:**
- VirusTotal: Free tier is 4 req/min - wait or upgrade
- AbuseIPDB: Free tier is 1000 req/day - spread queries
- Implement caching (already built-in)

## Support

For issues or questions:
- Check logs in `data/logs/`
- Review API provider documentation
- Open an issue on GitHub
- Contact your API provider support

## Quick Start Checklist

- [ ] Created accounts for all three threat intel APIs
- [ ] Set up email SMTP configuration
- [ ] Created Slack webhook (optional)
- [ ] Created .env file with all keys
- [ ] Ran configuration wizard
- [ ] Tested API keys
- [ ] Reviewed automation settings
- [ ] Read security best practices
- [ ] Backed up configuration securely

---

**Last Updated:** October 2024  
**Version:** 1.0.0

