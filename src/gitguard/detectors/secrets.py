from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from gitguard.core.models import Finding, FindingType, Severity


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.CRITICAL
    rule_id: str = ""
    description: str = ""
    languages: list[str] | None = None


SECRET_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern(name="AWS Access Key", pattern=re.compile(r"AKIA[0-9A-Z]{16}"), rule_id="SEC001", description="AWS Access Key ID detected"),
    SecretPattern(name="AWS Secret Key", pattern=re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), rule_id="SEC002", description="AWS Secret Access Key detected"),
    SecretPattern(name="AWS MWS Key", pattern=re.compile(r"amzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), rule_id="SEC002b", description="AWS MWS Auth Token detected"),
    SecretPattern(name="AWS ARN", pattern=re.compile(r"arn:aws:iam::[0-9]{12}:"), severity=Severity.LOW, rule_id="SEC002c", description="AWS ARN detected"),
    SecretPattern(name="AWS Session Token", pattern=re.compile(r"(?i)aws_session_token\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{100,}['\"]?"), rule_id="SEC002d", description="AWS Session Token detected"),

    # GitHub
    SecretPattern(name="GitHub Token", pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"), rule_id="SEC003", description="GitHub Personal Access Token detected"),
    SecretPattern(name="GitHub OAuth", pattern=re.compile(r"gho_[A-Za-z0-9]{36}"), rule_id="SEC004", description="GitHub OAuth Token detected"),
    SecretPattern(name="GitHub App Token", pattern=re.compile(r"(?:ghu|ghs)_[A-Za-z0-9]{36}"), rule_id="SEC004b", description="GitHub App Token detected"),
    SecretPattern(name="GitHub Fine-grained PAT", pattern=re.compile(r"github_pat_[A-Za-z0-9]{82}"), rule_id="SEC004c", description="GitHub Fine-grained PAT detected"),

    # GitLab
    SecretPattern(name="GitLab Token", pattern=re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), rule_id="SEC005", description="GitLab Personal Access Token detected"),
    SecretPattern(name="GitLab Pipeline Token", pattern=re.compile(r"glptt-[A-Za-z0-9\-_]{20,}"), rule_id="SEC005b", description="GitLab Pipeline Token detected"),
    SecretPattern(name="GitLab Runner Token", pattern=re.compile(r"glrt-[A-Za-z0-9\-_]{20,}"), rule_id="SEC005c", description="GitLab Runner Token detected"),

    # Slack
    SecretPattern(name="Slack Token", pattern=re.compile(r"xox[bpsar]-[0-9]{10,}-[A-Za-z0-9\-]+"), rule_id="SEC006", description="Slack Token detected"),
    SecretPattern(name="Slack Webhook", pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), rule_id="SEC007", description="Slack Webhook URL detected"),
    SecretPattern(name="Slack Bot Token", pattern=re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]+"), rule_id="SEC006b", description="Slack Bot Token detected"),
    SecretPattern(name="Slack User Token", pattern=re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}"), rule_id="SEC006c", description="Slack User Token detected"),
    SecretPattern(name="Slack App Token", pattern=re.compile(r"xoxe.xoxp-1-[A-Za-z0-9\-]{163}"), rule_id="SEC006d", description="Slack App Token detected"),

    # Google
    SecretPattern(name="Google API Key", pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"), rule_id="SEC008", description="Google API Key detected"),
    SecretPattern(name="Google OAuth", pattern=re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), rule_id="SEC009", description="Google OAuth Client ID detected"),
    SecretPattern(name="Google Service Account", pattern=re.compile(r'"type"\s*:\s*"service_account"'), severity=Severity.HIGH, rule_id="SEC009b", description="Google Service Account key detected"),
    SecretPattern(name="Google Firebase Key", pattern=re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), rule_id="SEC009c", description="Google Firebase Key detected"),

    # Stripe
    SecretPattern(name="Stripe Key", pattern=re.compile(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}"), rule_id="SEC010", description="Stripe API Key detected"),
    SecretPattern(name="Stripe Publishable Key", pattern=re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"), rule_id="SEC011", description="Stripe Publishable Key detected"),
    SecretPattern(name="Stripe Restricted Key", pattern=re.compile(r"rk_(live|test)_[0-9a-zA-Z]{24,}"), rule_id="SEC010b", description="Stripe Restricted Key detected"),
    SecretPattern(name="Stripe Webhook Secret", pattern=re.compile(r"whsec_[A-Za-z0-9]{32,}"), rule_id="SEC010c", description="Stripe Webhook Secret detected"),

    # Private Keys
    SecretPattern(name="Private Key Block", pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), severity=Severity.CRITICAL, rule_id="SEC012", description="Private key detected"),
    SecretPattern(name="SSH Private Key", pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), severity=Severity.CRITICAL, rule_id="SEC013", description="SSH private key detected"),
    SecretPattern(name="PGP Private Key", pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), severity=Severity.CRITICAL, rule_id="SEC014", description="PGP private key detected"),

    # Generic
    SecretPattern(name="Generic API Key", pattern=re.compile(r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?"), severity=Severity.HIGH, rule_id="SEC015", description="Potential API key detected"),
    SecretPattern(name="Generic Secret", pattern=re.compile(r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?"), severity=Severity.HIGH, rule_id="SEC016", description="Potential secret or password detected"),
    SecretPattern(name="Connection String", pattern=re.compile(r"(?i)(?:mongodb|mysql|postgres|redis|amqp|sqlite)://[^\s]+"), severity=Severity.HIGH, rule_id="SEC017", description="Database connection string detected"),
    SecretPattern(name="JWT Token", pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"), severity=Severity.HIGH, rule_id="SEC018", description="JWT token detected"),
    SecretPattern(name="Bearer Token", pattern=re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]+"), severity=Severity.HIGH, rule_id="SEC019", description="Bearer token detected"),
    SecretPattern(name="Base64 Encoded Secret", pattern=re.compile(r"(?i)(?:secret|password|key|token)\s*[=:]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?"), severity=Severity.MEDIUM, rule_id="SEC020", description="Potential base64-encoded secret detected"),

    # Twilio
    SecretPattern(name="Twilio API Key", pattern=re.compile(r"SK[0-9a-fA-F]{32}"), rule_id="SEC021", description="Twilio API Key detected"),
    SecretPattern(name="Twilio Account SID", pattern=re.compile(r"AC[a-z0-9]{32}"), severity=Severity.MEDIUM, rule_id="SEC022", description="Twilio Account SID detected"),
    SecretPattern(name="Twilio Auth Token", pattern=re.compile(r"(?i)twilio.*?auth.*?token.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC022b", description="Twilio Auth Token detected"),

    # SendGrid/Mailgun
    SecretPattern(name="SendGrid API Key", pattern=re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), rule_id="SEC023", description="SendGrid API Key detected"),
    SecretPattern(name="Mailgun API Key", pattern=re.compile(r"key-[0-9a-zA-Z]{32}"), rule_id="SEC024", description="Mailgun API Key detected"),
    SecretPattern(name="Mailgun Pub Key", pattern=re.compile(r"pubkey-[0-9a-zA-Z]{32}"), rule_id="SEC024b", description="Mailgun Public Key detected"),
    SecretPattern(name="Mailgun Signing Key", pattern=re.compile(r"signing_key-[0-9a-zA-Z]{32}"), rule_id="SEC024c", description="Mailgun Signing Key detected"),

    # Heroku
    SecretPattern(name="Heroku API Key", pattern=re.compile(r"(?i)heroku.*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), rule_id="SEC025", description="Heroku API Key detected"),

    # Package Registries
    SecretPattern(name="PyPI Token", pattern=re.compile(r"pypi-[A-Za-z0-9\-_]{60,}"), rule_id="SEC026", description="PyPI API Token detected"),
    SecretPattern(name="npm Token", pattern=re.compile(r"npm_[A-Za-z0-9]{36}"), rule_id="SEC027", description="npm Access Token detected"),
    SecretPattern(name="RubyGems API Key", pattern=re.compile(r"rubygems_[a-f0-9]{48}"), rule_id="SEC028", description="RubyGems API Key detected"),
    SecretPattern(name="Docker Hub Token", pattern=re.compile(r"dockerhub_[a-f0-9]{40}"), rule_id="SEC029", description="Docker Hub Access Token detected"),
    SecretPattern(name="NuGet API Key", pattern=re.compile(r"oy2[a-z0-9]{43}"), rule_id="SEC029b", description="NuGet API Key detected"),
    SecretPattern(name="Maven Central Token", pattern=re.compile(r"(?i)maven.*?token.*?['\"]?[A-Za-z0-9]{60,}['\"]?"), rule_id="SEC029c", description="Maven Central Token detected"),
    SecretPattern(name="CocoaPods Token", pattern=re.compile(r"(?i)cocoapods.*?token.*?['\"]?[A-Za-z0-9\-_]{40,}['\"]?"), rule_id="SEC029d", description="CocoaPods Token detected"),

    # DevOps
    SecretPattern(name="Terraform Cloud Token", pattern=re.compile(r"atlasv1\.[A-Za-z0-9\-_]{60,}"), rule_id="SEC030", description="Terraform Cloud API Token detected"),
    SecretPattern(name="Vault Token", pattern=re.compile(r"hvs\.[A-Za-z0-9]{24,}"), rule_id="SEC031", description="HashiCorp Vault Token detected"),
    SecretPattern(name="Ansible Vault Password", pattern=re.compile(r"(?i)ansible.*?vault.*?password.*?['\"]?[^\s'\"]{8,}['\"]?"), rule_id="SEC100", description="Ansible Vault Password detected"),
    SecretPattern(name="Consul Token", pattern=re.compile(r"(?i)consul.*?token.*?['\"]?[a-f0-9\-]{36}['\"]?"), rule_id="SEC031b", description="HashiCorp Consul Token detected"),
    SecretPattern(name="Nomad Token", pattern=re.compile(r"(?i)nomad.*?token.*?['\"]?[a-f0-9\-]{36}['\"]?"), rule_id="SEC031c", description="HashiCorp Nomad Token detected"),

    # E-commerce
    SecretPattern(name="Shopify Token", pattern=re.compile(r"shpat_[a-fA-F0-9]{32}"), rule_id="SEC032", description="Shopify Private App Token detected"),
    SecretPattern(name="Shopify Access Token", pattern=re.compile(r"shpca_[a-fA-F0-9]{32}"), rule_id="SEC033", description="Shopify Customer Account Access Token detected"),
    SecretPattern(name="Shopify Custom App Token", pattern=re.compile(r"shppa_[a-fA-F0-9]{32}"), rule_id="SEC032b", description="Shopify Custom App Access Token detected"),
    SecretPattern(name="WooCommerce Key", pattern=re.compile(r"(?i)woocommerce.*?(?:key|secret).*?['\"]?[a-f0-9]{40}['\"]?"), rule_id="SEC032c", description="WooCommerce API Key detected"),
    SecretPattern(name="Magento Token", pattern=re.compile(r"(?i)magento.*?token.*?['\"]?[a-zA-Z0-9]{32,}['\"]?"), rule_id="SEC032d", description="Magento Integration Token detected"),

    # Cloud Storage
    SecretPattern(name="Dropbox Access Token", pattern=re.compile(r"sl\.[A-Za-z0-9\-_]{60,}"), rule_id="SEC033b", description="Dropbox Access Token detected"),
    SecretPattern(name="Dropbox Short Lived Token", pattern=re.compile(r"sl\.U[A-Za-z0-9\-_]{60,}"), rule_id="SEC033c", description="Dropbox Short-Lived Token detected"),
    SecretPattern(name="Box Access Token", pattern=re.compile(r"(?i)box.*?access.*?token.*?['\"]?[a-zA-Z0-9]{32,}['\"]?"), rule_id="SEC033d", description="Box Access Token detected"),
    SecretPattern(name="AWS S3 Bucket Key", pattern=re.compile(r"(?i)s3.*?(?:access|secret).*?key.*?['\"]?[A-Za-z0-9/+=]{40}['\"]?"), rule_id="SEC033e", description="AWS S3 Bucket Key detected"),

    # AI/ML
    SecretPattern(name="OpenAI API Key", pattern=re.compile(r"sk-[A-Za-z0-9]{48}"), rule_id="SEC062", description="OpenAI API Key detected"),
    SecretPattern(name="OpenAI Organization Key", pattern=re.compile(r"org-[A-Za-z0-9]{24}"), rule_id="SEC063", description="OpenAI Organization Key detected"),
    SecretPattern(name="Anthropic API Key", pattern=re.compile(r"sk-ant-[A-Za-z0-9\-_]{93}AA"), rule_id="SEC062b", description="Anthropic API Key detected"),
    SecretPattern(name="Hugging Face Token", pattern=re.compile(r"hf_[A-Za-z0-9]{34}"), rule_id="SEC062c", description="Hugging Face Token detected"),
    SecretPattern(name="Replicate API Token", pattern=re.compile(r"r8_[A-Za-z0-9]{40}"), rule_id="SEC062d", description="Replicate API Token detected"),
    SecretPattern(name="Cohere API Key", pattern=re.compile(r"(?i)cohere.*?api.*?key.*?['\"]?[A-Za-z0-9]{40}['\"]?"), rule_id="SEC062e", description="Cohere API Key detected"),
    SecretPattern(name="Mistral API Key", pattern=re.compile(r"(?i)mistral.*?api.*?key.*?['\"]?[A-Za-z0-9]{32}['\"]?"), rule_id="SEC062f", description="Mistral API Key detected"),
    SecretPattern(name="Groq API Key", pattern=re.compile(r"gsk_[A-Za-z0-9]{52}"), rule_id="SEC062g", description="Groq API Key detected"),
    SecretPattern(name="Together API Key", pattern=re.compile(r"(?i)together.*?api.*?key.*?['\"]?[a-f0-9]{64}['\"]?"), rule_id="SEC062h", description="Together API Key detected"),

    # Analytics/Tracking
    SecretPattern(name="Segment Write Key", pattern=re.compile(r"(?i)segment.*?write.*?key.*?['\"]?[a-zA-Z0-9]{32}['\"]?"), rule_id="SEC034", description="Segment Write Key detected"),
    SecretPattern(name="Mixpanel Token", pattern=re.compile(r"(?i)mixpanel.*?(?:token|secret).*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC034b", description="Mixpanel Token detected"),
    SecretPattern(name="Amplitude API Key", pattern=re.compile(r"(?i)amplitude.*?api.*?key.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC034c", description="Amplitude API Key detected"),
    SecretPattern(name="Segment Source ID", pattern=re.compile(r"(?i)segment.*?source.*?id.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC034d", description="Segment Source ID detected"),

    # Monitoring
    SecretPattern(name="Datadog API Key", pattern=re.compile(r"(?i)datadog.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC040", description="Datadog API Key detected"),
    SecretPattern(name="Datadog App Key", pattern=re.compile(r"(?i)datadog.*?['\"]?[a-f0-9]{40}['\"]?"), rule_id="SEC041", description="Datadog Application Key detected"),
    SecretPattern(name="New Relic API Key", pattern=re.compile(r"NRAK-[A-Z0-9]{27}"), rule_id="SEC059", description="New Relic API Key detected"),
    SecretPattern(name="New Relic Insights Key", pattern=re.compile(r"NRI[A-Za-z0-9\-_]{32}"), rule_id="SEC060", description="New Relic Insights Key detected"),
    SecretPattern(name="New Relic License Key", pattern=re.compile(r"NRL[A-Za-z0-9]{40}"), rule_id="SEC060b", description="New Relic License Key detected"),
    SecretPattern(name="Sentry DSN", pattern=re.compile(r"https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+"), severity=Severity.LOW, rule_id="SEC072", description="Sentry DSN detected"),
    SecretPattern(name="Sentry Auth Token", pattern=re.compile(r"sntrys_[A-Za-z0-9_]{72,}"), rule_id="SEC072b", description="Sentry Auth Token detected"),
    SecretPattern(name="PagerDuty API Key", pattern=re.compile(r"(?i)pagerduty.*?api.*?key.*?['\"]?[a-zA-Z0-9]{20}['\"]?"), rule_id="SEC040b", description="PagerDuty API Key detected"),
    SecretPattern(name="PagerDuty Integration Key", pattern=re.compile(r"[a-f0-9]{32}"), severity=Severity.LOW, rule_id="SEC040c", description="Potential PagerDuty Integration Key detected"),
    SecretPattern(name="Grafana API Key", pattern=re.compile(r"(?i)grafana.*?api.*?key.*?['\"]?[a-zA-Z0-9]{32}['\"]?"), rule_id="SEC040d", description="Grafana API Key detected"),
    SecretPattern(name="Prometheus Remote Write Token", pattern=re.compile(r"(?i)prometheus.*?remote.*?write.*?token.*?['\"]?[a-zA-Z0-9\-_]{40,}['\"]?"), rule_id="SEC040e", description="Prometheus Remote Write Token detected"),

    # Version Control
    SecretPattern(name="Bitbucket App Password", pattern=re.compile(r"bbp_[A-Za-z0-9]{60}"), rule_id="SEC037", description="Bitbucket App Password detected"),
    SecretPattern(name="Bitbucket Access Token", pattern=re.compile(r"(?i)bitbucket.*?access.*?token.*?['\"]?[a-zA-Z0-9]{40}['\"]?"), rule_id="SEC037b", description="Bitbucket Access Token detected"),
    SecretPattern(name="Azure DevOps PAT", pattern=re.compile(r"(?i)azure.*?devops.*?pat.*?['\"]?[a-zA-Z0-9]{52}['\"]?"), rule_id="SEC037c", description="Azure DevOps Personal Access Token detected"),

    # CRM/Support
    SecretPattern(name="Salesforce Access Token", pattern=re.compile(r"(?i)salesforce.*?['\"]?00D[A-Za-z0-9]{12}!['\"]?"), rule_id="SEC089", description="Salesforce Access Token detected"),
    SecretPattern(name="Salesforce Refresh Token", pattern=re.compile(r"(?i)salesforce.*?refresh.*?token.*?['\"]?[A-Za-z0-9\-_]{40,}['\"]?"), rule_id="SEC089b", description="Salesforce Refresh Token detected"),
    SecretPattern(name="Zendesk API Token", pattern=re.compile(r"(?i)zendesk.*?['\"]?[A-Za-z0-9]{40}['\"]?"), rule_id="SEC081", description="Zendesk API Token detected"),
    SecretPattern(name="Intercom Access Token", pattern=re.compile(r"(?i)intercom.*?['\"]?dG9rZW46OjowIGlkOj[A-Za-z0-9\-_]+['\"]?"), rule_id="SEC053", description="Intercom Access Token detected"),
    SecretPattern(name="Freshdesk API Key", pattern=re.compile(r"(?i)freshdesk.*?api.*?key.*?['\"]?[A-Za-z0-9]{20}['\"]?"), rule_id="SEC053b", description="Freshdesk API Key detected"),
    SecretPattern(name="HubSpot API Key", pattern=re.compile(r"pat-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), rule_id="SEC052", description="HubSpot Private App Token detected"),

    # Communication
    SecretPattern(name="Discord Bot Token", pattern=re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"), rule_id="SEC006e", description="Discord Bot Token detected"),
    SecretPattern(name="Discord Webhook", pattern=re.compile(r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"), rule_id="SEC007b", description="Discord Webhook URL detected"),
    SecretPattern(name="Telegram Bot Token", pattern=re.compile(r"[0-9]+:AA[0-9A-Za-z\-_]{33}"), rule_id="SEC006f", description="Telegram Bot Token detected"),
    SecretPattern(name="Microsoft Teams Webhook", pattern=re.compile(r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@]+/IncomingWebhook/[A-Za-z0-9]+/[A-Za-z0-9\-]+"), rule_id="SEC007c", description="Microsoft Teams Webhook detected"),
    SecretPattern(name="Twilio SID", pattern=re.compile(r"AC[a-f0-9]{32}"), rule_id="SEC022", description="Twilio Account SID detected"),

    # Cryptocurrency
    SecretPattern(name="Coinbase API Key", pattern=re.compile(r"(?i)coinbase.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC083", description="Coinbase API Key detected"),
    SecretPattern(name="Binance API Key", pattern=re.compile(r"(?i)binance.*?api.*?key.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC083b", description="Binance API Key detected"),
    SecretPattern(name="Alchemy API Key", pattern=re.compile(r"alchemy_[A-Za-z0-9]{40}"), rule_id="SEC083c", description="Alchemy API Key detected"),
    SecretPattern(name="Infura API Key", pattern=re.compile(r"(?i)infura.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC083d", description="Infura API Key detected"),
    SecretPattern(name="Etherscan API Key", pattern=re.compile(r"(?i)etherscan.*?api.*?key.*?['\"]?[A-Z0-9]{34}['\"]?"), rule_id="SEC083e", description="Etherscan API Key detected"),

    # Email
    SecretPattern(name="Mailchimp API Key", pattern=re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"), rule_id="SEC024d", description="Mailchimp API Key detected"),
    SecretPattern(name="Postmark Server Token", pattern=re.compile(r"(?i)postmark.*?server.*?token.*?['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?"), rule_id="SEC024e", description="Postmark Server Token detected"),
    SecretPattern(name="SparkPost API Key", pattern=re.compile(r"(?i)sparkpost.*?api.*?key.*?['\"]?[a-f0-9]{40}['\"]?"), rule_id="SEC024f", description="SparkPost API Key detected"),
    SecretPattern(name="Mandrill API Key", pattern=re.compile(r"(?i)mandrill.*?api.*?key.*?['\"]?[A-Za-z0-9\-]{22}['\"]?"), rule_id="SEC024g", description="Mandrill API Key detected"),
    SecretPattern(name="Sendinblue API Key", pattern=re.compile(r"xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}"), rule_id="SEC024h", description="Sendinblue API Key detected"),

    # Payment
    SecretPattern(name="PayPal Client Secret", pattern=re.compile(r"(?i)paypal.*?client.*?secret.*?['\"]?[A-Za-z0-9\-_]{50,}['\"]?"), rule_id="SEC010d", description="PayPal Client Secret detected"),
    SecretPattern(name="Square Access Token", pattern=re.compile(r"sq0atp-[A-Za-z0-9\-_]{22}"), rule_id="SEC010e", description="Square Access Token detected"),
    SecretPattern(name="Square OAuth Secret", pattern=re.compile(r"sq0csp-[A-Za-z0-9\-_]{43}"), rule_id="SEC010f", description="Square OAuth Secret detected"),
    SecretPattern(name="Braintree Access Token", pattern=re.compile(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"), rule_id="SEC010g", description="Braintree Access Token detected"),
    SecretPattern(name="Adyen API Key", pattern=re.compile(r" AQEhmhm|AQE|AQEyhmhm|AQEyhmhx"), severity=Severity.HIGH, rule_id="SEC010h", description="Adyen API Key detected"),
    SecretPattern(name="Razorpay Key", pattern=re.compile(r"rzp_live_[A-Za-z0-9]{14}"), rule_id="SEC010i", description="Razorpay Live Key detected"),
    SecretPattern(name="Razorpay Test Key", pattern=re.compile(r"rzp_test_[A-Za-z0-9]{14}"), rule_id="SEC010j", description="Razorpay Test Key detected"),

    # CDN/Edge
    SecretPattern(name="Cloudflare API Key", pattern=re.compile(r"(?i)cloudflare.*?(?:api|global).*?key.*?['\"]?[a-f0-9]{37}['\"]?"), rule_id="SEC035", description="Cloudflare API Key detected"),
    SecretPattern(name="Cloudflare API Token", pattern=re.compile(r"(?i)cloudflare.*?api.*?token.*?['\"]?[A-Za-z0-9\-_]{40}['\"]?"), rule_id="SEC035b", description="Cloudflare API Token detected"),
    SecretPattern(name="Fastly API Token", pattern=re.compile(r"(?i)fastly.*?['\"]?[A-Za-z0-9\-_]{32,}['\"]?"), rule_id="SEC046", description="Fastly API Token detected"),
    SecretPattern(name="MaxCDN API Token", pattern=re.compile(r"(?i)maxcdn.*?api.*?token.*?['\"]?[a-f0-9]{64}['\"]?"), rule_id="SEC046b", description="MaxCDN API Token detected"),
    SecretPattern(name="KeyCDN API Key", pattern=re.compile(r"(?i)keycdn.*?api.*?key.*?['\"]?[a-f0-9]{64}['\"]?"), rule_id="SEC046c", description="KeyCDN API Key detected"),

    # Infrastructure
    SecretPattern(name="DigitalOcean Token", pattern=re.compile(r"dop_v1_[a-f0-9]{64}"), rule_id="SEC042", description="DigitalOcean Personal Access Token detected"),
    SecretPattern(name="DigitalOcean OAuth Token", pattern=re.compile(r"doo_v1_[a-f0-9]{64}"), rule_id="SEC043", description="DigitalOcean OAuth Token detected"),
    SecretPattern(name="Vultr API Key", pattern=re.compile(r"(?i)vultr.*?api.*?key.*?['\"]?[A-Z0-9]{36}['\"]?"), rule_id="SEC042b", description="Vultr API Key detected"),
    SecretPattern(name="Linode API Token", pattern=re.compile(r"(?i)linode.*?(?:api|personal).*?token.*?['\"]?[a-f0-9]{64}['\"]?"), rule_id="SEC042c", description="Linode API Token detected"),
    SecretPattern(name="Hetzner API Token", pattern=re.compile(r"(?i)hetzner.*?api.*?token.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC042d", description="Hetzner API Token detected"),
    SecretPattern(name="Scaleway API Key", pattern=re.compile(r"SCW[A-Z0-9]{20}"), rule_id="SEC071", description="Scaleway API Key detected"),
    SecretPattern(name="Vercel Access Token", pattern=re.compile(r"(?i)vercel.*?['\"]?[A-Za-z0-9]{24}['\"]?"), rule_id="SEC079", description="Vercel Access Token detected"),
    SecretPattern(name="Netlify Access Token", pattern=re.compile(r"nfp_[A-Za-z0-9]{40}"), rule_id="SEC058", description="Netlify Personal Access Token detected"),
    SecretPattern(name="Fly.io API Token", pattern=re.compile(r"fo1_[A-Za-z0-9\-_]{43}"), rule_id="SEC058b", description="Fly.io API Token detected"),
    SecretPattern(name="Render API Key", pattern=re.compile(r"rnd_[A-Za-z0-9]{32}"), rule_id="SEC058c", description="Render API Key detected"),
    SecretPattern(name="Railway Token", pattern=re.compile(r"(?i)railway.*?token.*?['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?"), rule_id="SEC058d", description="Railway Token detected"),

    # Database
    SecretPattern(name="MongoDB Connection String", pattern=re.compile(r"mongodb(\+srv)?://[^\s]+"), rule_id="SEC017b", description="MongoDB Connection String detected"),
    SecretPattern(name="MySQL Connection String", pattern=re.compile(r"mysql://[^\s]+"), rule_id="SEC017c", description="MySQL Connection String detected"),
    SecretPattern(name="PostgreSQL Connection String", pattern=re.compile(r"postgres(ql)?://[^\s]+"), rule_id="SEC017d", description="PostgreSQL Connection String detected"),
    SecretPattern(name="Redis Connection String", pattern=re.compile(r"redis://[^\s]+"), rule_id="SEC017e", description="Redis Connection String detected"),
    SecretPattern(name="Elasticsearch Connection String", pattern=re.compile(r"https?://[^\s]*elastic[^\s]*"), rule_id="SEC017f", description="Elasticsearch Connection String detected"),
    SecretPattern(name="RabbitMQ Connection String", pattern=re.compile(r"amqps?://[^\s]+"), rule_id="SEC017g", description="RabbitMQ Connection String detected"),
    SecretPattern(name="Cassandra Connection String", pattern=re.compile(r"cassandra://[^\s]+"), rule_id="SEC017h", description="Cassandra Connection String detected"),
    SecretPattern(name="CouchDB Connection String", pattern=re.compile(r"https?://[^\s]*couch[^\s]*"), rule_id="SEC017i", description="CouchDB Connection String detected"),

    # Identity/Auth
    SecretPattern(name="Auth0 Management API Token", pattern=re.compile(r"(?i)auth0.*?management.*?api.*?token.*?['\"]?[A-Za-z0-9\-_]{100,}['\"]?"), rule_id="SEC036", description="Auth0 Management API Token detected"),
    SecretPattern(name="Okta API Token", pattern=re.compile(r"(?i)okta.*?api.*?token.*?['\"]?[A-Za-z0-9]{40}['\"]?"), rule_id="SEC036b", description="Okta API Token detected"),
    SecretPattern(name="Firebase API Key", pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"), rule_id="SEC008b", description="Firebase API Key detected"),
    SecretPattern(name="Firebase Auth Token", pattern=re.compile(r"(?i)firebase.*?(?:auth|id).*?token.*?['\"]?[A-Za-z0-9\-_\.]{100,}['\"]?"), rule_id="SEC008c", description="Firebase Auth Token detected"),
    SecretPattern(name="Supabase Key", pattern=re.compile(r"sbp_[A-Za-z0-9]{40,}"), rule_id="SEC008d", description="Supabase API Key detected"),

    # CI/CD
    SecretPattern(name="CircleCI Token", pattern=re.compile(r"(?i)circleci.*?(?:token|api).*?['\"]?[a-f0-9]{40}['\"]?"), rule_id="SEC038", description="CircleCI Token detected"),
    SecretPattern(name="Travis CI Token", pattern=re.compile(r"travis_com_[A-Za-z0-9]{20}"), rule_id="SEC076", description="Travis CI Token detected"),
    SecretPattern(name="Jenkins API Token", pattern=re.compile(r"(?i)jenkins.*?api.*?token.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC038b", description="Jenkins API Token detected"),
    SecretPattern(name="Buildkite API Token", pattern=re.compile(r"bkua_[a-f0-9]{40}"), rule_id="SEC038c", description="Buildkite API Token detected"),
    SecretPattern(name="Semaphore API Token", pattern=re.compile(r"(?i)semaphore.*?api.*?token.*?['\"]?[a-f0-9]{64}['\"]?"), rule_id="SEC038d", description="Semaphore API Token detected"),
    SecretPattern(name="GitHub Actions Secret", pattern=re.compile(r"(?i)github.*?actions.*?secret.*?['\"]?[A-Za-z0-9\-_]{40,}['\"]?"), rule_id="SEC038e", description="GitHub Actions Secret detected"),

    # Cloud
    SecretPattern(name="Azure Storage Account Key", pattern=re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"), severity=Severity.CRITICAL, rule_id="SEC085", description="Azure Storage Account Key detected"),
    SecretPattern(name="Azure AD Client Secret", pattern=re.compile(r"(?i)azure.*?client.*?secret.*?['\"]?[A-Za-z0-9\-_.~+/]{32,}['\"]?"), rule_id="SEC086", description="Azure AD Client Secret detected"),
    SecretPattern(name="Azure Cosmos DB Key", pattern=re.compile(r"(?i)AccountEndpoint=https://[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"), severity=Severity.CRITICAL, rule_id="SEC092", description="Azure Cosmos DB Connection String detected"),
    SecretPattern(name="Azure Service Bus Key", pattern=re.compile(r"(?i)Endpoint=sb://[^;]+;SharedAccessKey=[A-Za-z0-9+/=]{44}"), severity=Severity.HIGH, rule_id="SEC092b", description="Azure Service Bus Key detected"),
    SecretPattern(name="Azure SignalR Connection String", pattern=re.compile(r"(?i)Endpoint=https://[^;]+;AccessKey=[A-Za-z0-9+/=]{44}"), severity=Severity.HIGH, rule_id="SEC092c", description="Azure SignalR Connection String detected"),
    SecretPattern(name="Azure Event Hub Connection String", pattern=re.compile(r"(?i)Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]{44}"), severity=Severity.HIGH, rule_id="SEC092d", description="Azure Event Hub Connection String detected"),
    SecretPattern(name="IBM Cloud API Key", pattern=re.compile(r"(?i)ibm.*?api.*?key.*?['\"]?[A-Za-z0-9\-_]{44}['\"]?"), rule_id="SEC087", description="IBM Cloud API Key detected"),
    SecretPattern(name="Alibaba Access Key", pattern=re.compile(r"AK[A-Z0-9]{20}"), rule_id="SEC084", description="Alibaba Cloud Access Key detected"),
    SecretPattern(name="Alibaba Secret Key", pattern=re.compile(r"(?i)alibaba.*?secret.*?key.*?['\"]?[A-Za-z0-9]{30}['\"]?"), rule_id="SEC084b", description="Alibaba Cloud Secret Key detected"),
    SecretPattern(name="OCI Private Key", pattern=re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), severity=Severity.CRITICAL, rule_id="SEC088", description="Oracle Cloud Infrastructure Private Key detected"),
    SecretPattern(name="OCI Auth Token", pattern=re.compile(r"(?i)oci.*?auth.*?token.*?['\"]?[A-Za-z0-9]{60}['\"]?"), rule_id="SEC088b", description="OCI Auth Token detected"),

    # Kubernetes
    SecretPattern(name="Kubernetes Service Account Token", pattern=re.compile(r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9\-_]+"), severity=Severity.HIGH, rule_id="SEC093", description="Kubernetes Service Account Token detected"),
    SecretPattern(name="Kubernetes kubeconfig", pattern=re.compile(r"apiVersion:\s*v1.*?clusters:.*?cluster:", re.DOTALL), severity=Severity.HIGH, rule_id="SEC093b", description="Kubernetes kubeconfig detected"),

    # Databricks
    SecretPattern(name="Databricks Token", pattern=re.compile(r"dapi[A-Za-z0-9]{32}"), rule_id="SEC094", description="Databricks Personal Access Token detected"),
    SecretPattern(name="Databricks Secret", pattern=re.compile(r"dbsc[A-Za-z0-9]{32}"), rule_id="SEC095", description="Databricks Secret detected"),

    # Snowflake
    SecretPattern(name="Snowflake Account Key", pattern=re.compile(r"(?i)snowflake.*?(?:account|key).*?['\"]?[A-Za-z0-9\-_]{40,}['\"]?"), rule_id="SEC095b", description="Snowflake Account Key detected"),

    # Redis
    SecretPattern(name="Redis Cloud API Key", pattern=re.compile(r"(?i)redis.*?cloud.*?api.*?key.*?['\"]?[A-Za-z0-9\-_]{40}['\"]?"), rule_id="SEC095c", description="Redis Cloud API Key detected"),

    # Messaging
    SecretPattern(name="RabbitMQ Password", pattern=re.compile(r"(?i)rabbitmq.*?password.*?['\"]?[^\s'\"]{8,}['\"]?"), rule_id="SEC095d", description="RabbitMQ Password detected"),
    SecretPattern(name="Kafka API Key", pattern=re.compile(r"(?i)kafka.*?api.*?key.*?['\"]?[A-Za-z0-9]{16,}['\"]?"), rule_id="SEC095e", description="Kafka API Key detected"),
    SecretPattern(name="Confluent API Key", pattern=re.compile(r"(?i)confluent.*?api.*?key.*?['\"]?[a-zA-Z0-9]{16}['\"]?"), rule_id="SEC095f", description="Confluent API Key detected"),

    # Other
    SecretPattern(name="Asana Access Token", pattern=re.compile(r"1/[0-9]+:[a-f0-9]{32}"), severity=Severity.MEDIUM, rule_id="SEC035", description="Asana Access Token detected"),
    SecretPattern(name="Atlassian API Token", pattern=re.compile(r"ATATT[A-Za-z0-9]{60}"), rule_id="SEC036", description="Atlassian API Token detected"),
    SecretPattern(name="Confluence API Token", pattern=re.compile(r"(?i)confluence.*?api.*?token.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC036b", description="Confluence API Token detected"),
    SecretPattern(name="Jira API Token", pattern=re.compile(r"(?i)jira.*?api.*?token.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC036c", description="Jira API Token detected"),
    SecretPattern(name="Linear API Key", pattern=re.compile(r"lin_api_[A-Za-z0-9]{40}"), rule_id="SEC054", description="Linear API Key detected"),
    SecretPattern(name="Notion API Key", pattern=re.compile(r"ntn_[A-Za-z0-9]{40,}"), rule_id="SEC054b", description="Notion API Key detected"),
    SecretPattern(name="Airtable API Key", pattern=re.compile(r"key[0-9A-Za-z]{14}"), severity=Severity.MEDIUM, rule_id="SEC034", description="Airtable API Key detected"),
    SecretPattern(name="Airtable Personal Access Token", pattern=re.compile(r"pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}"), rule_id="SEC034b", description="Airtable Personal Access Token detected"),
    SecretPattern(name="Contentful API Key", pattern=re.compile(r"CFPAT-[A-Za-z0-9\-_]{43}"), rule_id="SEC039", description="Contentful Personal Access Token detected"),
    SecretPattern(name="Lob API Key", pattern=re.compile(r"(test|live)_[a-f0-9]{35}"), rule_id="SEC055", description="Lob API Key detected"),
    SecretPattern(name="Ngrok API Token", pattern=re.compile(r"ngrok_[a-zA-Z0-9]{40}"), rule_id="SEC061", description="Ngrok API Token detected"),
    SecretPattern(name="Pulumi Access Token", pattern=re.compile(r"pul-[a-f0-9]{40}"), rule_id="SEC067", description="Pulumi Access Token detected"),
    SecretPattern(name="PlanetScale Token", pattern=re.compile(r"pscale_tkn_[A-Za-z0-9\-_]{43}"), rule_id="SEC064", description="PlanetScale OAuth Token detected"),
    SecretPattern(name="PlanetScale Password", pattern=re.compile(r"pscale_pw_[A-Za-z0-9\-_]{43}"), rule_id="SEC065", description="PlanetScale Service Password detected"),
    SecretPattern(name="Postman API Key", pattern=re.compile(r"PMAK-[A-Za-z0-9]{24}\.[A-Za-z0-9]{66}"), rule_id="SEC066", description="Postman API Key detected"),
    SecretPattern(name="ReadMe API Key", pattern=re.compile(r"rdme_[a-f0-9]{64}"), rule_id="SEC069", description="ReadMe API Key detected"),
    SecretPattern(name="Snyk Token", pattern=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{24}"), severity=Severity.LOW, rule_id="SEC073", description="Potential Snyk Token detected"),
    SecretPattern(name="SonarCloud Token", pattern=re.compile(r"(?i)sq.*?[a-f0-9]{40}"), rule_id="SEC074", description="SonarCloud Token detected"),
    SecretPattern(name="Typeform Token", pattern=re.compile(r"tfp_[A-Za-z0-9\-_]{40}"), rule_id="SEC078", description="Typeform Personal Access Token detected"),
    SecretPattern(name="Travis CI Token", pattern=re.compile(r"travis_com_[A-Za-z0-9]{20}"), rule_id="SEC076", description="Travis CI Token detected"),
    SecretPattern(name="Zoom JWT Token", pattern=re.compile(r"(?i)zoom.*?['\"]?[A-Za-z0-9]{64}['\"]?"), rule_id="SEC082", description="Zoom JWT Token detected"),
    SecretPattern(name="Age Encryption Key", pattern=re.compile(r"age[12][A-Za-z0-9]{58}"), rule_id="SEC091", description="Age Encryption Key detected"),
    SecretPattern(name="Vault Unseal Key", pattern=re.compile(r"(?i)vault.*?unseal.*?key.*?['\"]?[A-Za-z0-9+/]{44}['\"]?"), severity=Severity.CRITICAL, rule_id="SEC098", description="HashiCorp Vault Unseal Key detected"),
    SecretPattern(name="Vault Root Token", pattern=re.compile(r"hvs\.[A-Za-z0-9]{24,}"), severity=Severity.CRITICAL, rule_id="SEC099", description="HashiCorp Vault Root Token detected"),
    SecretPattern(name="Mattermost Access Token", pattern=re.compile(r"(?i)mattermost.*?['\"]?[A-Za-z0-9]{26}['\"]?"), rule_id="SEC096", description="Mattermost Access Token detected"),
    SecretPattern(name="MinIO Secret Key", pattern=re.compile(r"(?i)minio.*?secret.*?key.*?['\"]?[A-Za-z0-9]{40}['\"]?"), rule_id="SEC097", description="MinIO Secret Key detected"),

    # More Cloud Services
    SecretPattern(name="Cloudinary URL", pattern=re.compile(r"cloudinary://[0-9]+:[A-Za-z0-9]+@[A-Za-z0-9]+"), rule_id="SEC033f", description="Cloudinary URL detected"),
    SecretPattern(name="Mapbox Token", pattern=re.compile(r"pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{60,}"), rule_id="SEC033g", description="Mapbox Public Token detected"),
    SecretPattern(name="Algolia API Key", pattern=re.compile(r"(?i)algolia.*?(?:admin|search).*?key.*?['\"]?[a-f0-9]{32}['\"]?"), rule_id="SEC033h", description="Algolia API Key detected"),
    SecretPattern(name="Twilio SendGrid", pattern=re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), rule_id="SEC023", description="SendGrid API Key detected"),
    SecretPattern(name="Plaid API Key", pattern=re.compile(r"(?i)plaid.*?(?:client|secret).*?['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?"), rule_id="SEC010k", description="Plaid API Key detected"),
    SecretPattern(name="Twilio Account SID", pattern=re.compile(r"AC[a-f0-9]{32}"), rule_id="SEC022", description="Twilio Account SID detected"),
    SecretPattern(name="Twilio API Key", pattern=re.compile(r"SK[a-f0-9]{32}"), rule_id="SEC021", description="Twilio API Key detected"),
]


def scan_for_secrets(file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if "example" in stripped.lower() or "placeholder" in stripped.lower():
            continue
        if "test" in file_path.parts or "mock" in file_path.parts:
            continue
        if file_path.suffix in (".md", ".txt", ".rst"):
            continue

        for secret_pattern in SECRET_PATTERNS:
            if secret_pattern.languages:
                suffix = file_path.suffix.lstrip(".")
                if suffix not in secret_pattern.languages:
                    continue

            match = secret_pattern.pattern.search(stripped)
            if match:
                findings.append(
                    Finding(
                        finding_type=FindingType.SECRET,
                        severity=secret_pattern.severity,
                        message=secret_pattern.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=stripped[:120],
                        rule_id=secret_pattern.rule_id,
                        suggestion=f"Remove or rotate the {secret_pattern.name}. Use environment variables instead.",
                    )
                )

    return findings
