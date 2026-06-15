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
    verified: bool = False


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        rule_id="SEC001",
        description="AWS Access Key ID detected",
    ),
    SecretPattern(
        name="AWS Secret Key",
        pattern=re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
        rule_id="SEC002",
        description="AWS Secret Access Key detected",
    ),
    SecretPattern(
        name="AWS MWS Key",
        pattern=re.compile(r"amzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        rule_id="SEC002b",
        description="AWS MWS Auth Token detected",
    ),
    SecretPattern(
        name="AWS ARN",
        pattern=re.compile(r"arn:aws:iam::[0-9]{12}:"),
        severity=Severity.LOW,
        rule_id="SEC002c",
        description="AWS ARN detected - verify if sensitive",
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
        rule_id="SEC003",
        description="GitHub Personal Access Token detected",
    ),
    SecretPattern(
        name="GitHub OAuth",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36}"),
        rule_id="SEC004",
        description="GitHub OAuth Token detected",
    ),
    SecretPattern(
        name="GitHub App Token",
        pattern=re.compile(r"(?:ghu|ghs)_[A-Za-z0-9]{36}"),
        rule_id="SEC004b",
        description="GitHub App Token detected",
    ),
    SecretPattern(
        name="GitLab Token",
        pattern=re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        rule_id="SEC005",
        description="GitLab Personal Access Token detected",
    ),
    SecretPattern(
        name="GitLab Pipeline Token",
        pattern=re.compile(r"glptt-[A-Za-z0-9\-_]{20,}"),
        rule_id="SEC005b",
        description="GitLab Pipeline Token detected",
    ),
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[bpsar]-[0-9]{10,}-[A-Za-z0-9\-]+"),
        rule_id="SEC006",
        description="Slack Token detected",
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        rule_id="SEC007",
        description="Slack Webhook URL detected",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        rule_id="SEC008",
        description="Google API Key detected",
    ),
    SecretPattern(
        name="Google OAuth",
        pattern=re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
        rule_id="SEC009",
        description="Google OAuth Client ID detected",
    ),
    SecretPattern(
        name="Google Service Account",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        severity=Severity.HIGH,
        rule_id="SEC009b",
        description="Google Service Account key detected",
    ),
    SecretPattern(
        name="Stripe Key",
        pattern=re.compile(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}"),
        rule_id="SEC010",
        description="Stripe API Key detected",
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"),
        rule_id="SEC011",
        description="Stripe Publishable Key detected",
    ),
    SecretPattern(
        name="Private Key Block",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC012",
        description="Private key detected",
    ),
    SecretPattern(
        name="SSH Private Key",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC013",
        description="SSH private key detected",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC014",
        description="PGP private key detected",
    ),
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?"),
        severity=Severity.HIGH,
        rule_id="SEC015",
        description="Potential API key detected",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?"),
        severity=Severity.HIGH,
        rule_id="SEC016",
        description="Potential secret or password detected",
    ),
    SecretPattern(
        name="Connection String",
        pattern=re.compile(r"(?i)(?:mongodb|mysql|postgres|redis|amqp|sqlite)://[^\s]+"),
        severity=Severity.HIGH,
        rule_id="SEC017",
        description="Database connection string detected",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"),
        severity=Severity.HIGH,
        rule_id="SEC018",
        description="JWT token detected",
    ),
    SecretPattern(
        name="Bearer Token",
        pattern=re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]+"),
        severity=Severity.HIGH,
        rule_id="SEC019",
        description="Bearer token detected",
    ),
    SecretPattern(
        name="Base64 Encoded Secret",
        pattern=re.compile(r"(?i)(?:secret|password|key|token)\s*[=:]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?"),
        severity=Severity.MEDIUM,
        rule_id="SEC020",
        description="Potential base64-encoded secret detected",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        rule_id="SEC021",
        description="Twilio API Key detected",
    ),
    SecretPattern(
        name="Twilio Account SID",
        pattern=re.compile(r"AC[a-z0-9]{32}"),
        severity=Severity.MEDIUM,
        rule_id="SEC022",
        description="Twilio Account SID detected",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        rule_id="SEC023",
        description="SendGrid API Key detected",
    ),
    SecretPattern(
        name="Mailgun API Key",
        pattern=re.compile(r"key-[0-9a-zA-Z]{32}"),
        rule_id="SEC024",
        description="Mailgun API Key detected",
    ),
    SecretPattern(
        name="Heroku API Key",
        pattern=re.compile(r"(?i)heroku.*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        rule_id="SEC025",
        description="Heroku API Key detected",
    ),
    SecretPattern(
        name="PyPI Token",
        pattern=re.compile(r"pypi-[A-Za-z0-9\-_]{60,}"),
        rule_id="SEC026",
        description="PyPI API Token detected",
    ),
    SecretPattern(
        name="npm Token",
        pattern=re.compile(r"npm_[A-Za-z0-9]{36}"),
        rule_id="SEC027",
        description="npm Access Token detected",
    ),
    SecretPattern(
        name="RubyGems API Key",
        pattern=re.compile(r"rubygems_[a-f0-9]{48}"),
        rule_id="SEC028",
        description="RubyGems API Key detected",
    ),
    SecretPattern(
        name="Docker Hub Token",
        pattern=re.compile(r"dockerhub_[a-f0-9]{40}"),
        rule_id="SEC029",
        description="Docker Hub Access Token detected",
    ),
    SecretPattern(
        name="Terraform Cloud Token",
        pattern=re.compile(r"atlasv1\.[A-Za-z0-9\-_]{60,}"),
        rule_id="SEC030",
        description="Terraform Cloud API Token detected",
    ),
    SecretPattern(
        name="Vault Token",
        pattern=re.compile(r"hvs\.[A-Za-z0-9]{24,}"),
        rule_id="SEC031",
        description="HashiCorp Vault Token detected",
    ),
    SecretPattern(
        name="Shopify Token",
        pattern=re.compile(r"shpat_[a-fA-F0-9]{32}"),
        rule_id="SEC032",
        description="Shopify Private App Token detected",
    ),
    SecretPattern(
        name="Shopify Access Token",
        pattern=re.compile(r"shpca_[a-fA-F0-9]{32}"),
        rule_id="SEC033",
        description="Shopify Customer Account Access Token detected",
    ),
    SecretPattern(
        name="Airtable API Key",
        pattern=re.compile(r"key[0-9A-Za-z]{14}"),
        severity=Severity.MEDIUM,
        rule_id="SEC034",
        description="Airtable API Key detected",
    ),
    SecretPattern(
        name="Asana Access Token",
        pattern=re.compile(r"1/[0-9]+:[a-f0-9]{32}"),
        severity=Severity.MEDIUM,
        rule_id="SEC035",
        description="Asana Access Token detected",
    ),
    SecretPattern(
        name="Atlassian API Token",
        pattern=re.compile(r"ATATT[A-Za-z0-9]{60}"),
        rule_id="SEC036",
        description="Atlassian API Token detected",
    ),
    SecretPattern(
        name="Bitbucket App Password",
        pattern=re.compile(r"bbp_[A-Za-z0-9]{60}"),
        rule_id="SEC037",
        description="Bitbucket App Password detected",
    ),
    SecretPattern(
        name="CircleCI Token",
        pattern=re.compile(r"[0-9a-f]{40}"),
        severity=Severity.LOW,
        rule_id="SEC038",
        description="Potential CircleCI Token detected",
    ),
    SecretPattern(
        name="Contentful API Key",
        pattern=re.compile(r"CFPAT-[A-Za-z0-9\-_]{43}"),
        rule_id="SEC039",
        description="Contentful Personal Access Token detected",
    ),
    SecretPattern(
        name="Datadog API Key",
        pattern=re.compile(r"(?i)datadog.*?['\"]?[a-f0-9]{32}['\"]?"),
        rule_id="SEC040",
        description="Datadog API Key detected",
    ),
    SecretPattern(
        name="Datadog App Key",
        pattern=re.compile(r"(?i)datadog.*?['\"]?[a-f0-9]{40}['\"]?"),
        rule_id="SEC041",
        description="Datadog Application Key detected",
    ),
    SecretPattern(
        name="DigitalOcean Token",
        pattern=re.compile(r"dop_v1_[a-f0-9]{64}"),
        rule_id="SEC042",
        description="DigitalOcean Personal Access Token detected",
    ),
    SecretPattern(
        name="DigitalOcean OAuth Token",
        pattern=re.compile(r"doo_v1_[a-f0-9]{64}"),
        rule_id="SEC043",
        description="DigitalOcean OAuth Token detected",
    ),
    SecretPattern(
        name="Dynatrace Token",
        pattern=re.compile(r"dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}"),
        rule_id="SEC044",
        description="Dynatrace API Token detected",
    ),
    SecretPattern(
        name="Elastic Cloud API Key",
        pattern=re.compile(r"(?i)elastic.*?['\"]?[A-Za-z0-9]{64}['\"]?"),
        rule_id="SEC045",
        description="Elastic Cloud API Key detected",
    ),
    SecretPattern(
        name="Fastly API Token",
        pattern=re.compile(r"(?i)fastly.*?['\"]?[A-Za-z0-9\-_]{32,}['\"]?"),
        rule_id="SEC046",
        description="Fastly API Token detected",
    ),
    SecretPattern(
        name="Firebase Key",
        pattern=re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
        severity=Severity.MEDIUM,
        rule_id="SEC047",
        description="Firebase Cloud Messaging Server Key detected",
    ),
    SecretPattern(
        name="Flutterwave Secret Key",
        pattern=re.compile(r"FLWSECK-[a-f0-9]{32}-X"),
        rule_id="SEC048",
        description="Flutterwave Secret Key detected",
    ),
    SecretPattern(
        name="Flutterwave Public Key",
        pattern=re.compile(r"FLWPUBK-[a-f0-9]{32}-X"),
        rule_id="SEC049",
        description="Flutterwave Public Key detected",
    ),
    SecretPattern(
        name="Gitter Access Token",
        pattern=re.compile(r"[0-9a-f]{40}"),
        severity=Severity.LOW,
        rule_id="SEC050",
        description="Potential Gitter Access Token detected",
    ),
    SecretPattern(
        name="Hashicorp Terraform",
        pattern=re.compile(r"vault_[a-zA-Z0-9]{14,}"),
        rule_id="SEC051",
        description="HashiCorp Terraform Token detected",
    ),
    SecretPattern(
        name="HubSpot API Key",
        pattern=re.compile(r"pat-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
        rule_id="SEC052",
        description="HubSpot Private App Token detected",
    ),
    SecretPattern(
        name="Intercom Access Token",
        pattern=re.compile(r"(?i)intercom.*?['\"]?dG9rZW46OjowIGlkOj[A-Za-z0-9\-_]+['\"]?"),
        rule_id="SEC053",
        description="Intercom Access Token detected",
    ),
    SecretPattern(
        name="Linear API Key",
        pattern=re.compile(r"lin_api_[A-Za-z0-9]{40}"),
        rule_id="SEC054",
        description="Linear API Key detected",
    ),
    SecretPattern(
        name="Lob API Key",
        pattern=re.compile(r"(test|live)_[a-f0-9]{35}"),
        rule_id="SEC055",
        description="Lob API Key detected",
    ),
    SecretPattern(
        name="Maxmind License Key",
        pattern=re.compile(r"(?i)maxmind.*?['\"]?[A-Za-z0-9]{32,}['\"]?"),
        rule_id="SEC056",
        description="Maxmind License Key detected",
    ),
    SecretPattern(
        name="MessageBird API Key",
        pattern=re.compile(r"MD[0-9a-zA-Z]{25}"),
        rule_id="SEC057",
        description="MessageBird API Key detected",
    ),
    SecretPattern(
        name="Netlify Access Token",
        pattern=re.compile(r"nfp_[A-Za-z0-9]{40}"),
        rule_id="SEC058",
        description="Netlify Personal Access Token detected",
    ),
    SecretPattern(
        name="New Relic API Key",
        pattern=re.compile(r"NRAK-[A-Z0-9]{27}"),
        rule_id="SEC059",
        description="New Relic API Key detected",
    ),
    SecretPattern(
        name="New Relic Insights Key",
        pattern=re.compile(r"NRI[A-Za-z0-9\-_]{32}"),
        rule_id="SEC060",
        description="New Relic Insights Key detected",
    ),
    SecretPattern(
        name="Ngrok API Token",
        pattern=re.compile(r"ngrok_[a-zA-Z0-9]{40}"),
        rule_id="SEC061",
        description="Ngrok API Token detected",
    ),
    SecretPattern(
        name="OpenAI API Key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{48}"),
        rule_id="SEC062",
        description="OpenAI API Key detected",
    ),
    SecretPattern(
        name="OpenAI Organization Key",
        pattern=re.compile(r"org-[A-Za-z0-9]{24}"),
        rule_id="SEC063",
        description="OpenAI Organization Key detected",
    ),
    SecretPattern(
        name="PlanetScale Token",
        pattern=re.compile(r"pscale_tkn_[A-Za-z0-9\-_]{43}"),
        rule_id="SEC064",
        description="PlanetScale OAuth Token detected",
    ),
    SecretPattern(
        name="PlanetScale Password",
        pattern=re.compile(r"pscale_pw_[A-Za-z0-9\-_]{43}"),
        rule_id="SEC065",
        description="PlanetScale Service Password detected",
    ),
    SecretPattern(
        name="Postman API Key",
        pattern=re.compile(r"PMAK-[A-Za-z0-9]{24}\.[A-Za-z0-9]{66}"),
        rule_id="SEC066",
        description="Postman API Key detected",
    ),
    SecretPattern(
        name="Pulumi Access Token",
        pattern=re.compile(r"pul-[a-f0-9]{40}"),
        rule_id="SEC067",
        description="Pulumi Access Token detected",
    ),
    SecretPattern(
        name="RapidAPI Key",
        pattern=re.compile(r"[a-f0-9]{32}"),
        severity=Severity.LOW,
        rule_id="SEC068",
        description="Potential RapidAPI Key detected",
    ),
    SecretPattern(
        name="ReadMe API Key",
        pattern=re.compile(r"rdme_[a-f0-9]{64}"),
        rule_id="SEC069",
        description="ReadMe API Key detected",
    ),
    SecretPattern(
        name="RubyGems API Key",
        pattern=re.compile(r"rubygems_[a-f0-9]{48}"),
        rule_id="SEC070",
        description="RubyGems API Key detected",
    ),
    SecretPattern(
        name="Scaleway API Key",
        pattern=re.compile(r"SCW[A-Z0-9]{20}"),
        rule_id="SEC071",
        description="Scaleway API Key detected",
    ),
    SecretPattern(
        name="Sentry DSN",
        pattern=re.compile(r"https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+"),
        severity=Severity.LOW,
        rule_id="SEC072",
        description="Sentry DSN detected",
    ),
    SecretPattern(
        name="Snyk Token",
        pattern=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{24}"),
        severity=Severity.LOW,
        rule_id="SEC073",
        description="Potential Snyk Token detected",
    ),
    SecretPattern(
        name="SonarCloud Token",
        pattern=re.compile(r"(?i)sq.*?[a-f0-9]{40}"),
        rule_id="SEC074",
        description="SonarCloud Token detected",
    ),
    SecretPattern(
        name="Supabase Service Role Key",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"),
        severity=Severity.HIGH,
        rule_id="SEC075",
        description="Supabase Service Role Key detected",
    ),
    SecretPattern(
        name="Travis CI Token",
        pattern=re.compile(r"travis_com_[A-Za-z0-9]{20}"),
        rule_id="SEC076",
        description="Travis CI Token detected",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        rule_id="SEC077",
        description="Twilio API Key detected",
    ),
    SecretPattern(
        name="Typeform Token",
        pattern=re.compile(r"tfp_[A-Za-z0-9\-_]{40}"),
        rule_id="SEC078",
        description="Typeform Personal Access Token detected",
    ),
    SecretPattern(
        name="Vercel Access Token",
        pattern=re.compile(r"(?i)vercel.*?['\"]?[A-Za-z0-9]{24}['\"]?"),
        rule_id="SEC079",
        description="Vercel Access Token detected",
    ),
    SecretPattern(
        name="WebhookSite Token",
        pattern=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        severity=Severity.LOW,
        rule_id="SEC080",
        description="Potential WebhookSite Token detected",
    ),
    SecretPattern(
        name="Zendesk API Token",
        pattern=re.compile(r"(?i)zendesk.*?['\"]?[A-Za-z0-9]{40}['\"]?"),
        rule_id="SEC081",
        description="Zendesk API Token detected",
    ),
    SecretPattern(
        name="Zoom JWT Token",
        pattern=re.compile(r"(?i)zoom.*?['\"]?[A-Za-z0-9]{64}['\"]?"),
        rule_id="SEC082",
        description="Zoom JWT Token detected",
    ),
    SecretPattern(
        name="Coinbase API Key",
        pattern=re.compile(r"(?i)coinbase.*?['\"]?[A-Za-z0-9]{64}['\"]?"),
        rule_id="SEC083",
        description="Coinbase API Key detected",
    ),
    SecretPattern(
        name="Alibaba Access Key",
        pattern=re.compile(r"AK[A-Z0-9]{20}"),
        rule_id="SEC084",
        description="Alibaba Cloud Access Key detected",
    ),
    SecretPattern(
        name="Azure Storage Account Key",
        pattern=re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
        severity=Severity.CRITICAL,
        rule_id="SEC085",
        description="Azure Storage Account Key detected",
    ),
    SecretPattern(
        name="Azure AD Client Secret",
        pattern=re.compile(r"(?i)azure.*?client.*?secret.*?['\"]?[A-Za-z0-9\-_.~+/]{32,}['\"]?"),
        rule_id="SEC086",
        description="Azure AD Client Secret detected",
    ),
    SecretPattern(
        name="IBM Cloud API Key",
        pattern=re.compile(r"(?i)ibm.*?api.*?key.*?['\"]?[A-Za-z0-9\-_]{44}['\"]?"),
        rule_id="SEC087",
        description="IBM Cloud API Key detected",
    ),
    SecretPattern(
        name="OCI Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        rule_id="SEC088",
        description="Oracle Cloud Infrastructure Private Key detected",
    ),
    SecretPattern(
        name="Salesforce Access Token",
        pattern=re.compile(r"(?i)salesforce.*?['\"]?00D[A-Za-z0-9]{12}!['\"]?"),
        rule_id="SEC089",
        description="Salesforce Access Token detected",
    ),
    SecretPattern(
        name="SAP Service Key",
        pattern=re.compile(r"(?i)sap.*?client.*?secret.*?['\"]?[A-Za-z0-9]{40,}['\"]?"),
        rule_id="SEC090",
        description="SAP Service Key detected",
    ),
    SecretPattern(
        name="Age Encryption Key",
        pattern=re.compile(r"age[12][A-Za-z0-9]{58}"),
        rule_id="SEC091",
        description="Age Encryption Key detected",
    ),
    SecretPattern(
        name="Cosmos DB Connection String",
        pattern=re.compile(r"(?i)AccountEndpoint=https://[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
        severity=Severity.CRITICAL,
        rule_id="SEC092",
        description="Azure Cosmos DB Connection String detected",
    ),
    SecretPattern(
        name="Kubernetes Service Account Token",
        pattern=re.compile(r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9\-_]+"),
        severity=Severity.HIGH,
        rule_id="SEC093",
        description="Kubernetes Service Account Token detected",
    ),
    SecretPattern(
        name="Databricks Token",
        pattern=re.compile(r"dapi[A-Za-z0-9]{32}"),
        rule_id="SEC094",
        description="Databricks Personal Access Token detected",
    ),
    SecretPattern(
        name="Databricks Secret",
        pattern=re.compile(r"dbsc[A-Za-z0-9]{32}"),
        rule_id="SEC095",
        description="Databricks Secret detected",
    ),
    SecretPattern(
        name="Mattermost Access Token",
        pattern=re.compile(r"(?i)mattermost.*?['\"]?[A-Za-z0-9]{26}['\"]?"),
        rule_id="SEC096",
        description="Mattermost Access Token detected",
    ),
    SecretPattern(
        name="MinIO Secret Key",
        pattern=re.compile(r"(?i)minio.*?secret.*?key.*?['\"]?[A-Za-z0-9]{40}['\"]?"),
        rule_id="SEC097",
        description="MinIO Secret Key detected",
    ),
    SecretPattern(
        name="Vault Unseal Key",
        pattern=re.compile(r"(?i)vault.*?unseal.*?key.*?['\"]?[A-Za-z0-9+/]{44}['\"]?"),
        severity=Severity.CRITICAL,
        rule_id="SEC098",
        description="HashiCorp Vault Unseal Key detected",
    ),
    SecretPattern(
        name="Vault Root Token",
        pattern=re.compile(r"hvs\.[A-Za-z0-9]{24,}"),
        severity=Severity.CRITICAL,
        rule_id="SEC099",
        description="HashiCorp Vault Root Token detected",
    ),
    SecretPattern(
        name="Ansible Vault Password",
        pattern=re.compile(r"(?i)ansible.*?vault.*?password.*?['\"]?[^\s'\"]{8,}['\"]?"),
        rule_id="SEC100",
        description="Ansible Vault Password detected",
    ),
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
