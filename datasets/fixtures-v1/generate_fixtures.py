#!/usr/bin/env python3
"""Deterministic Generator for ETW Synthetic Fixture Dataset (v1).

Generates exactly 68 synthetic scanner findings partitioned across:
- 34 TruffleHog v3 findings (JSONL format: trufflehog_fixtures.jsonl)
- 34 Gitleaks v8 findings (JSON array format: gitleaks_fixtures.json)
- 68 Ground Truth labels (JSON format: ground_truth.json)

ALL CREDENTIALS AND IDENTIFIERS ARE ENTIRELY FICTIONAL SYNTHETIC VALUES.
DO NOT USE REAL SECRETS.
"""

import json
from pathlib import Path

DATASET_DIR = Path(__file__).parent


def create_fixtures():
    # -------------------------------------------------------------
    # 1. True Candidate Secrets (15 findings: 8 TruffleHog, 7 Gitleaks)
    # -------------------------------------------------------------
    cat1_th = [
        {
            "id": "FIX-01",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/prod-payments",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "services/stripe_client.py", "line": 28, "commit": "c0ffee112233", "repository": "org/prod-payments"}}},
                "DetectorName": "StripeLiveKey",
                "Verified": True,
                "Raw": "sk_live_51NyXZ7FakeProdStripeKey998877AABBCC",
                "Redacted": "sk_live_********************************AABBCC"
            }
        },
        {
            "id": "FIX-02",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/prod-cloud",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "deploy/terraform/main.tf", "line": 45, "commit": "c0ffee112234", "repository": "org/prod-cloud"}}},
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": "AKIA99FAKEPRODAWSKEY01",
                "Redacted": "AKIA****************01"
            }
        },
        {
            "id": "FIX-03",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/auth-service",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "auth/tokens.py", "line": 102, "commit": "c0ffee112235", "repository": "org/auth-service"}}},
                "DetectorName": "GitHubToken",
                "Verified": False,
                "Raw": "ghp_FakeLiveGitHubPersonalAccessToken123456",
                "Redacted": "ghp_**********************************3456"
            }
        },
        {
            "id": "FIX-04",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/backend-core",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "config/production.json", "line": 15, "commit": "c0ffee112236", "repository": "org/backend-core"}}},
                "DetectorName": "SlackWebhook",
                "Verified": False,
                "Raw": "https://hooks.slack.com/services/T999/B888/FakeLiveSlackWebhookToken99",
                "Redacted": "https://hooks.slack.com/services/T999/B888/****************ken99"
            }
        },
        {
            "id": "FIX-05",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/database-migrator",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "scripts/db_sync.sh", "line": 8, "commit": "c0ffee112237", "repository": "org/database-migrator"}}},
                "DetectorName": "PostgresURI",
                "Verified": False,
                "Raw": "postgresql://dbadmin:pAssw0rdF4keProdSecret99@prod-db.internal.net:5432/orders",
                "Redacted": "postgresql://dbadmin:*****************@prod-db.internal.net:5432/orders"
            }
        },
        {
            "id": "FIX-06",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/notifications",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "mailer/sendgrid.py", "line": 34, "commit": "c0ffee112238", "repository": "org/notifications"}}},
                "DetectorName": "SendGridKey",
                "Verified": False,
                "Raw": "SG.FakeLiveSendGridAPIKeyPart1.FakeLiveSendGridKeyPart2XYZ9988",
                "Redacted": "SG.****************************************************88"
            }
        },
        {
            "id": "FIX-07",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/comms",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "sms/twilio.py", "line": 12, "commit": "c0ffee112239", "repository": "org/comms"}}},
                "DetectorName": "TwilioAuthToken",
                "Verified": False,
                "Raw": "AC998877665544332211aabbccddeeff00",
                "Redacted": "AC********************************00"
            }
        },
        {
            "id": "FIX-08",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/ai-engine",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "models/inference.py", "line": 50, "commit": "c0ffee112240", "repository": "org/ai-engine"}}},
                "DetectorName": "OpenAIKey",
                "Verified": False,
                "Raw": "sk-proj-FakeLiveOpenAITokenForInferenceEngine9988776655",
                "Redacted": "sk-proj-******************************************6655"
            }
        },
    ]

    cat1_gl = [
        {
            "id": "FIX-09",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/analytics",
            "gl_record": {
                "Description": "Google API Key",
                "StartLine": 19, "EndLine": 19, "StartColumn": 10, "EndColumn": 49,
                "Match": "AIzaSyFakeLiveGoogleCloudPlatformApiKey99",
                "Secret": "AIzaSyFakeLiveGoogleCloudPlatformApiKey99",
                "File": "pipeline/bigquery.py",
                "Commit": "d00d00112233", "Author": "bob", "Email": "bob@org.com", "Date": "2026-03-01T10:00:00Z",
                "RuleID": "gcp-api-key"
            }
        },
        {
            "id": "FIX-10",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/search-infra",
            "gl_record": {
                "Description": "Algolia Admin Key",
                "StartLine": 25, "EndLine": 25, "StartColumn": 15, "EndColumn": 47,
                "Match": "99aabbccddeeff001122334455667788",
                "Secret": "99aabbccddeeff001122334455667788",
                "File": "indexing/algolia.py",
                "Commit": "d00d00112234", "Author": "carol", "Email": "carol@org.com", "Date": "2026-03-02T10:00:00Z",
                "RuleID": "algolia-admin-key"
            }
        },
        {
            "id": "FIX-11",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/customer-portal",
            "gl_record": {
                "Description": "Sentry DSN Auth",
                "StartLine": 14, "EndLine": 14, "StartColumn": 5, "EndColumn": 70,
                "Match": "https://fakePubSentryKey99:fakeSecSentrySecret88@o99.ingest.sentry.io/123",
                "Secret": "fakeSecSentrySecret88",
                "File": "src/monitoring.ts",
                "Commit": "d00d00112235", "Author": "dave", "Email": "dave@org.com", "Date": "2026-03-03T10:00:00Z",
                "RuleID": "sentry-dsn"
            }
        },
        {
            "id": "FIX-12",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/billing-service",
            "gl_record": {
                "Description": "Square Access Token",
                "StartLine": 31, "EndLine": 31, "StartColumn": 12, "EndColumn": 55,
                "Match": "sq0atp-FakeSquareProdAccessTokenXYZ123456",
                "Secret": "sq0atp-FakeSquareProdAccessTokenXYZ123456",
                "File": "pos/square.py",
                "Commit": "d00d00112236", "Author": "eve", "Email": "eve@org.com", "Date": "2026-03-04T10:00:00Z",
                "RuleID": "square-access-token"
            }
        },
        {
            "id": "FIX-13",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/infra-ops",
            "gl_record": {
                "Description": "Datadog API Key",
                "StartLine": 8, "EndLine": 8, "StartColumn": 20, "EndColumn": 52,
                "Match": "11223344556677889900aabbccddeeff",
                "Secret": "11223344556677889900aabbccddeeff",
                "File": "k8s/datadog-values.yaml",
                "Commit": "d00d00112237", "Author": "frank", "Email": "frank@org.com", "Date": "2026-03-05T10:00:00Z",
                "RuleID": "datadog-api-key"
            }
        },
        {
            "id": "FIX-14",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/gateway",
            "gl_record": {
                "Description": "JWT Secret Signer",
                "StartLine": 44, "EndLine": 44, "StartColumn": 14, "EndColumn": 54,
                "Match": "superSecureJwtSigningKeyForProductionGateway99!",
                "Secret": "superSecureJwtSigningKeyForProductionGateway99!",
                "File": "middleware/jwt.go",
                "Commit": "d00d00112238", "Author": "grace", "Email": "grace@org.com", "Date": "2026-03-06T10:00:00Z",
                "RuleID": "generic-secret"
            }
        },
        {
            "id": "FIX-15",
            "category": "true_candidate_secret",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/reporting",
            "gl_record": {
                "Description": "HubSpot Private App Token",
                "StartLine": 12, "EndLine": 12, "StartColumn": 18, "EndColumn": 60,
                "Match": "pat-na1-FakeHubspotLiveTokenForReportingJob99",
                "Secret": "pat-na1-FakeHubspotLiveTokenForReportingJob99",
                "File": "crm/hubspot.py",
                "Commit": "d00d00112239", "Author": "heidi", "Email": "heidi@org.com", "Date": "2026-03-07T10:00:00Z",
                "RuleID": "hubspot-api-key"
            }
        },
    ]

    # -------------------------------------------------------------
    # 2. Documentation Placeholders (12 findings: 6 TruffleHog, 6 Gitleaks)
    # -------------------------------------------------------------
    cat2_th = [
        {
            "id": "FIX-16",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/sdk-python",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "docs/setup.md", "line": 15, "repository": "org/sdk-python"}}},
                "DetectorName": "APIKey", "Verified": False,
                "Raw": "YOUR_API_KEY_HERE", "Redacted": "YOUR_API_KEY_HERE"
            }
        },
        {
            "id": "FIX-17",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/docs",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "tutorials/auth.md", "line": 42, "repository": "org/docs"}}},
                "DetectorName": "AWS", "Verified": False,
                "Raw": "AKIAIOSFODNN7EXAMPLE", "Redacted": "AKIA****************"
            }
        },
        {
            "id": "FIX-18",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/api-reference",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "README.md", "line": 60, "repository": "org/api-reference"}}},
                "DetectorName": "BearerToken", "Verified": False,
                "Raw": "<insert-token-here>", "Redacted": "<insert-token-here>"
            }
        },
        {
            "id": "FIX-19",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/cli-tool",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "config.example.yaml", "line": 5, "repository": "org/cli-tool"}}},
                "DetectorName": "GenericSecret", "Verified": False,
                "Raw": "REPLACE_WITH_YOUR_SECRET_KEY", "Redacted": "REPLACE_WITH_YOUR_SECRET_KEY"
            }
        },
        {
            "id": "FIX-20",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/sample-app",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "sample.env", "line": 4, "repository": "org/sample-app"}}},
                "DetectorName": "GenericPassword", "Verified": False,
                "Raw": "changeme_example_password", "Redacted": "changeme_example_password"
            }
        },
        {
            "id": "FIX-21",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/web-starter",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "docs/quickstart.rst", "line": 10, "repository": "org/web-starter"}}},
                "DetectorName": "APIKey", "Verified": False,
                "Raw": "00000000000000000000000000000000", "Redacted": "00000000000000000000000000000000"
            }
        },
    ]

    cat2_gl = [
        {
            "id": "FIX-22",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/frontend",
            "gl_record": {
                "Description": "Generic Token",
                "StartLine": 8, "EndLine": 8, "StartColumn": 1, "EndColumn": 25,
                "Match": "DUMMY_TOKEN_FOR_DOCS_123", "Secret": "DUMMY_TOKEN_FOR_DOCS_123",
                "File": "docs/api_guide.md", "RuleID": "generic-token"
            }
        },
        {
            "id": "FIX-23",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/examples",
            "gl_record": {
                "Description": "OpenAI Sample",
                "StartLine": 12, "EndLine": 12, "StartColumn": 10, "EndColumn": 40,
                "Match": "sk-example-openai-sample-key-xxxx", "Secret": "sk-example-openai-sample-key-xxxx",
                "File": "examples/basic_prompt.py", "RuleID": "openai-key"
            }
        },
        {
            "id": "FIX-24",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/integrations",
            "gl_record": {
                "Description": "Stripe Doc Key",
                "StartLine": 20, "EndLine": 20, "StartColumn": 15, "EndColumn": 45,
                "Match": "sk_test_placeholder_key_for_doc", "Secret": "sk_test_placeholder_key_for_doc",
                "File": "docs/payments.md", "RuleID": "stripe-key"
            }
        },
        {
            "id": "FIX-25",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/docker-templates",
            "gl_record": {
                "Description": "Sample DB Pass",
                "StartLine": 10, "EndLine": 10, "StartColumn": 5, "EndColumn": 30,
                "Match": "INSERT_PASSWORD_HERE", "Secret": "INSERT_PASSWORD_HERE",
                "File": "docker-compose.sample.yml", "RuleID": "db-password"
            }
        },
        {
            "id": "FIX-26",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/mobile-sdk",
            "gl_record": {
                "Description": "Placeholder Auth",
                "StartLine": 5, "EndLine": 5, "StartColumn": 1, "EndColumn": 25,
                "Match": "TODO_REPLACE_WITH_REAL_AUTH", "Secret": "TODO_REPLACE_WITH_REAL_AUTH",
                "File": "README.md", "RuleID": "generic-api"
            }
        },
        {
            "id": "FIX-27",
            "category": "documentation_placeholder",
            "expected_classification": "likely_placeholder",
            "expected_priority": "P4_low",
            "asset_scope": "org/templates",
            "gl_record": {
                "Description": "Example Token",
                "StartLine": 18, "EndLine": 18, "StartColumn": 20, "EndColumn": 45,
                "Match": "example_token_replace_me", "Secret": "example_token_replace_me",
                "File": "config.dist.json", "RuleID": "generic-api"
            }
        },
    ]

    # -------------------------------------------------------------
    # 3. Unit Test Fixtures (10 findings: 5 TruffleHog, 5 Gitleaks)
    # -------------------------------------------------------------
    cat3_th = [
        {
            "id": "FIX-28",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/core-api",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "tests/test_auth.py", "line": 22, "repository": "org/core-api"}}},
                "DetectorName": "APIKey", "Verified": False,
                "Raw": "test_mock_secret_key_1234567890", "Redacted": "test_mock_********************"
            }
        },
        {
            "id": "FIX-29",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/billing",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "tests/fixtures/stripe_mocks.py", "line": 15, "repository": "org/billing"}}},
                "DetectorName": "StripeTestKey", "Verified": False,
                "Raw": "sk_test_mock_unit_test_key_abc123", "Redacted": "sk_test_**********************"
            }
        },
        {
            "id": "FIX-30",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/storage",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "src/tests/test_s3_upload.py", "line": 40, "repository": "org/storage"}}},
                "DetectorName": "AWS", "Verified": False,
                "Raw": "AKIAIOSFODNN7TESTTEST", "Redacted": "AKIA****************"
            }
        },
        {
            "id": "FIX-31",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/gateway",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "spec/requests/auth_spec.rb", "line": 33, "repository": "org/gateway"}}},
                "DetectorName": "BearerToken", "Verified": False,
                "Raw": "unit_test_mock_bearer_token_xyz99", "Redacted": "unit_test_********************"
            }
        },
        {
            "id": "FIX-32",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/client-lib",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "test/mocks/credentials.json", "line": 4, "repository": "org/client-lib"}}},
                "DetectorName": "GenericSecret", "Verified": False,
                "Raw": "mock_credential_for_offline_test", "Redacted": "mock_credential_for_offline_test"
            }
        },
    ]

    cat3_gl = [
        {
            "id": "FIX-33",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/auth",
            "gl_record": {
                "Description": "Test Secret",
                "StartLine": 50, "EndLine": 50, "StartColumn": 10, "EndColumn": 40,
                "Match": "test_dummy_jwt_secret_key_abc", "Secret": "test_dummy_jwt_secret_key_abc",
                "File": "tests/unit/test_tokens.py", "RuleID": "jwt-secret"
            }
        },
        {
            "id": "FIX-34",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/database",
            "gl_record": {
                "Description": "Test DB Connection",
                "StartLine": 8, "EndLine": 8, "StartColumn": 5, "EndColumn": 50,
                "Match": "sqlite://testuser:testpass123@localhost/testdb", "Secret": "testpass123",
                "File": "conftest.py", "RuleID": "db-conn"
            }
        },
        {
            "id": "FIX-35",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/messaging",
            "gl_record": {
                "Description": "Mock RabbitMQ",
                "StartLine": 12, "EndLine": 12, "StartColumn": 15, "EndColumn": 45,
                "Match": "amqp://guest:guest@localhost:5672", "Secret": "guest",
                "File": "tests/fixtures/broker.py", "RuleID": "amqp-conn"
            }
        },
        {
            "id": "FIX-36",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/web-service",
            "gl_record": {
                "Description": "Mock Client Secret",
                "StartLine": 30, "EndLine": 30, "StartColumn": 8, "EndColumn": 45,
                "Match": "mock_client_secret_unit_test_only", "Secret": "mock_client_secret_unit_test_only",
                "File": "src/__tests__/auth.test.ts", "RuleID": "client-secret"
            }
        },
        {
            "id": "FIX-37",
            "category": "unit_test_fixture",
            "expected_classification": "likely_test_value",
            "expected_priority": "P4_low",
            "asset_scope": "org/mobile",
            "gl_record": {
                "Description": "Test API Key",
                "StartLine": 14, "EndLine": 14, "StartColumn": 12, "EndColumn": 40,
                "Match": "test_api_key_mock_response_123", "Secret": "test_api_key_mock_response_123",
                "File": "app/src/test/java/MockServer.kt", "RuleID": "api-key"
            }
        },
    ]

    # -------------------------------------------------------------
    # 4. Canary Tokens (5 findings: 3 TruffleHog, 2 Gitleaks)
    # -------------------------------------------------------------
    cat4_th = [
        {
            "id": "FIX-38",
            "category": "canary_token",
            "expected_classification": "likely_canary",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/honey-pot",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "canary/aws_token.env", "line": 2, "repository": "org/honey-pot"}}},
                "DetectorName": "CanaryToken", "Verified": False,
                "Raw": "http://canarytokens.com/feedback/tags/terms/traffic/abcdef1234567890/post.jsp",
                "Redacted": "http://canarytokens.com/****************************************"
            }
        },
        {
            "id": "FIX-39",
            "category": "canary_token",
            "expected_classification": "likely_canary",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/trap-infra",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "secrets/canary_aws.json", "line": 5, "repository": "org/trap-infra"}}},
                "DetectorName": "AWS", "Verified": False,
                "Raw": "AKIAIOSFODNN7CANARYKEY1", "Redacted": "AKIA****************"
            }
        },
    ]

    cat4_gl = [
        {
            "id": "FIX-40",
            "category": "canary_token",
            "expected_classification": "likely_canary",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/security-defense",
            "gl_record": {
                "Description": "Canary URL",
                "StartLine": 8, "EndLine": 8, "StartColumn": 1, "EndColumn": 50,
                "Match": "https://canarytokens.org/generate/contact/abcdef998877",
                "Secret": "https://canarytokens.org/generate/contact/abcdef998877",
                "File": "tripwires/webhook.py", "RuleID": "canary-url"
            }
        },
        {
            "id": "FIX-41",
            "category": "canary_token",
            "expected_classification": "likely_canary",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/defense",
            "gl_record": {
                "Description": "Canary Token",
                "StartLine": 16, "EndLine": 16, "StartColumn": 10, "EndColumn": 60,
                "Match": "canarytoken-dns-probe-marker-9988aabbcc",
                "Secret": "canarytoken-dns-probe-marker-9988aabbcc",
                "File": "internal/defense/canary.txt", "RuleID": "canary-token"
            }
        },
        {
            "id": "FIX-42",
            "category": "canary_token",
            "expected_classification": "likely_canary",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/honeynet",
            "gl_record": {
                "Description": "Canary URL",
                "StartLine": 20, "EndLine": 20, "StartColumn": 5, "EndColumn": 65,
                "Match": "http://canarytokens.com/articles/sample/visit.html",
                "Secret": "http://canarytokens.com/articles/sample/visit.html",
                "File": "honeypot/link.html", "RuleID": "canary-url"
            }
        },
    ]

    # -------------------------------------------------------------
    # 5. Repeated Sightings / Duplicates (10 findings: 5 TruffleHog, 5 Gitleaks)
    # (Shared secret values appearing across multiple files/commits in same repo)
    # -------------------------------------------------------------
    shared_dup_secret_1 = "ghp_SyntheticSharedDuplicateToken11223344"
    shared_dup_secret_2 = "sk_live_SyntheticSharedStripeKey99887766"
    shared_dup_secret_3 = "AKIA_SYNTHETIC_DUPLICATE_AWS_KEY_5544"
    shared_dup_secret_4 = "AIzaSySyntheticSharedGoogleApiKey887766"
    shared_dup_secret_5 = "sq0atp-SyntheticSharedSquareToken123456"

    cat5_th = [
        {
            "id": "FIX-43",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "services/a/client.py", "line": 10, "commit": "comm01", "repository": "org/monorepo"}}},
                "DetectorName": "GitHubToken", "Verified": False,
                "Raw": shared_dup_secret_1, "Redacted": "ghp_********************************"
            }
        },
        {
            "id": "FIX-44",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "services/b/client.py", "line": 25, "commit": "comm02", "repository": "org/monorepo"}}},
                "DetectorName": "GitHubToken", "Verified": False,
                "Raw": shared_dup_secret_1, "Redacted": "ghp_********************************"
            }
        },
        {
            "id": "FIX-45",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/monorepo",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "billing/stripe.py", "line": 40, "commit": "comm03", "repository": "org/monorepo"}}},
                "DetectorName": "StripeLiveKey", "Verified": True,
                "Raw": shared_dup_secret_2, "Redacted": "sk_live_********************************"
            }
        },
        {
            "id": "FIX-46",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P1_urgent",
            "asset_scope": "org/monorepo",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "billing/v2/stripe_v2.py", "line": 12, "commit": "comm04", "repository": "org/monorepo"}}},
                "DetectorName": "StripeLiveKey", "Verified": True,
                "Raw": shared_dup_secret_2, "Redacted": "sk_live_********************************"
            }
        },
        {
            "id": "FIX-47",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "cloud/aws_init.py", "line": 5, "commit": "comm05", "repository": "org/monorepo"}}},
                "DetectorName": "AWS", "Verified": False,
                "Raw": shared_dup_secret_3, "Redacted": "AKIA****************"
            }
        },
    ]

    cat5_gl = [
        {
            "id": "FIX-48",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "gl_record": {
                "Description": "AWS Key duplicate",
                "StartLine": 18, "EndLine": 18, "StartColumn": 1, "EndColumn": 35,
                "Match": shared_dup_secret_3, "Secret": shared_dup_secret_3,
                "File": "cloud/backup_aws.py", "RuleID": "aws-access-key"
            }
        },
        {
            "id": "FIX-49",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "gl_record": {
                "Description": "Google API Key 1",
                "StartLine": 30, "EndLine": 30, "StartColumn": 10, "EndColumn": 48,
                "Match": shared_dup_secret_4, "Secret": shared_dup_secret_4,
                "File": "gcp/maps.py", "RuleID": "gcp-api-key"
            }
        },
        {
            "id": "FIX-50",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "gl_record": {
                "Description": "Google API Key 2",
                "StartLine": 22, "EndLine": 22, "StartColumn": 12, "EndColumn": 50,
                "Match": shared_dup_secret_4, "Secret": shared_dup_secret_4,
                "File": "gcp/translate.py", "RuleID": "gcp-api-key"
            }
        },
        {
            "id": "FIX-51",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "gl_record": {
                "Description": "Square Token 1",
                "StartLine": 15, "EndLine": 15, "StartColumn": 1, "EndColumn": 45,
                "Match": shared_dup_secret_5, "Secret": shared_dup_secret_5,
                "File": "pos/terminal.py", "RuleID": "square-access-token"
            }
        },
        {
            "id": "FIX-52",
            "category": "duplicate_sighting",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "org/monorepo",
            "gl_record": {
                "Description": "Square Token 2",
                "StartLine": 28, "EndLine": 28, "StartColumn": 1, "EndColumn": 45,
                "Match": shared_dup_secret_5, "Secret": shared_dup_secret_5,
                "File": "pos/kiosk.py", "RuleID": "square-access-token"
            }
        },
    ]

    # -------------------------------------------------------------
    # 6. Cross-Repository Collisions (4 findings: 2 TruffleHog, 2 Gitleaks)
    # (Same secret in 2 distinct repositories: MUST NOT merge into 1 Case!)
    # -------------------------------------------------------------
    cross_repo_secret_1 = "ghp_SyntheticCrossRepoTokenAlpha998877"
    cross_repo_secret_2 = "AKIA_CROSS_REPO_AWS_BETA_9988776655"

    cat6_th = [
        {
            "id": "FIX-53",
            "category": "cross_repo_collision",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "customer-a/web-app",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "src/api.py", "line": 15, "repository": "customer-a/web-app"}}},
                "DetectorName": "GitHubToken", "Verified": False,
                "Raw": cross_repo_secret_1, "Redacted": "ghp_********************************"
            }
        },
        {
            "id": "FIX-54",
            "category": "cross_repo_collision",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "customer-b/internal-tools",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "scripts/sync.py", "line": 20, "repository": "customer-b/internal-tools"}}},
                "DetectorName": "GitHubToken", "Verified": False,
                "Raw": cross_repo_secret_1, "Redacted": "ghp_********************************"
            }
        },
    ]

    cat6_gl = [
        {
            "id": "FIX-55",
            "category": "cross_repo_collision",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "tenant-x/cloud-deploy",
            "gl_record": {
                "Description": "AWS Cross Repo",
                "StartLine": 10, "EndLine": 10, "StartColumn": 1, "EndColumn": 35,
                "Match": cross_repo_secret_2, "Secret": cross_repo_secret_2,
                "File": "infra/main.tf", "RuleID": "aws-access-key"
            }
        },
        {
            "id": "FIX-56",
            "category": "cross_repo_collision",
            "expected_classification": "candidate_secret",
            "expected_priority": "P2_high",
            "asset_scope": "tenant-y/staging-env",
            "gl_record": {
                "Description": "AWS Cross Repo",
                "StartLine": 14, "EndLine": 14, "StartColumn": 1, "EndColumn": 35,
                "Match": cross_repo_secret_2, "Secret": cross_repo_secret_2,
                "File": "envs/staging.tf", "RuleID": "aws-access-key"
            }
        },
    ]

    # -------------------------------------------------------------
    # 7. Ambiguous / Incomplete Context (6 findings: 3 TruffleHog, 3 Gitleaks)
    # -------------------------------------------------------------
    cat7_th = [
        {
            "id": "FIX-57",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/legacy",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "utils/hash.py", "line": 88, "repository": "org/legacy"}}},
                "DetectorName": "HighEntropyString", "Verified": False,
                "Raw": "4a7f9b2c8e1d5a3f", "Redacted": "4a7f************"
            }
        },
        {
            "id": "FIX-58",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/scripts",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "build/hash_check.sh", "line": 12, "repository": "org/scripts"}}},
                "DetectorName": "GenericKey", "Verified": False,
                "Raw": "abcdef0123456789abcdef", "Redacted": "abcd**************ef"
            }
        },
        {
            "id": "FIX-59",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/crypto-lab",
            "th_record": {
                "SourceMetadata": {"Data": {"Git": {"file": "benchmarks/nonce.py", "line": 30, "repository": "org/crypto-lab"}}},
                "DetectorName": "EntropyDetector", "Verified": False,
                "Raw": "x9K2pL4mN8qR1tV7", "Redacted": "x9K2************"
            }
        },
    ]

    cat7_gl = [
        {
            "id": "FIX-60",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/data-lake",
            "gl_record": {
                "Description": "Hex hash match",
                "StartLine": 5, "EndLine": 5, "StartColumn": 10, "EndColumn": 30,
                "Match": "7f8e9d0a1b2c3d4e5f6a", "Secret": "7f8e9d0a1b2c3d4e5f6a",
                "File": "checksums/sha1.txt", "RuleID": "entropy-hash"
            }
        },
        {
            "id": "FIX-61",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/ml-pipeline",
            "gl_record": {
                "Description": "UUID Match",
                "StartLine": 12, "EndLine": 12, "StartColumn": 1, "EndColumn": 37,
                "Match": "c4ca4238-a0b9-3382-8dcc-509a6f75849b", "Secret": "c4ca4238-a0b9-3382-8dcc-509a6f75849b",
                "File": "models/guid_map.json", "RuleID": "uuid-match"
            }
        },
        {
            "id": "FIX-62",
            "category": "ambiguous_context",
            "expected_classification": "needs_review",
            "expected_priority": "P3_normal",
            "asset_scope": "org/frontend",
            "gl_record": {
                "Description": "Short string",
                "StartLine": 40, "EndLine": 40, "StartColumn": 14, "EndColumn": 28,
                "Match": "base64EncodedVal", "Secret": "base64EncodedVal",
                "File": "static/assets.js", "RuleID": "short-secret"
            }
        },
    ]

    # -------------------------------------------------------------
    # 8. Malformed / Edge-Case Inputs (6 findings: 3 TruffleHog, 3 Gitleaks)
    # (Truncated JSON lines, missing secret fields, invalid types)
    # -------------------------------------------------------------
    cat8_th = [
        {
            "id": "FIX-63",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "is_malformed_raw_line": "{ \"DetectorName\": \"AWS\", \"Raw\": \"broken_json_line_missing_closing_brace",
            "th_record": None
        },
        {
            "id": "FIX-64",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "th_record": {
                # Missing "Raw" secret field completely
                "SourceMetadata": {"Data": {"Git": {"file": "empty_finding.py", "line": 1, "repository": "org/quarantine"}}},
                "DetectorName": "EmptyFinding",
                "Verified": False
            }
        },
        {
            "id": "FIX-65",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "th_record": {
                # Invalid Raw type (number instead of string)
                "SourceMetadata": {"Data": {"Git": {"file": "bad_type.py", "line": 4, "repository": "org/quarantine"}}},
                "DetectorName": "NumericRaw",
                "Raw": 123456789
            }
        },
    ]

    cat8_gl = [
        {
            "id": "FIX-66",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "gl_record": {
                # Missing Secret/Match field
                "Description": "Missing Secret",
                "File": "incomplete.py",
                "StartLine": 5,
                "RuleID": "missing-secret"
            }
        },
        {
            "id": "FIX-67",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "gl_record": {
                # Non-string Secret field (array instead of string)
                "Description": "Array Secret",
                "File": "array_secret.py",
                "Secret": ["invalid", "secret", "array"],
                "RuleID": "array-secret"
            }
        },
        {
            "id": "FIX-68",
            "category": "malformed_edge_case",
            "expected_classification": "quarantined",
            "expected_priority": "N/A",
            "asset_scope": "org/quarantine",
            "gl_record": {
                # Empty dictionary with missing all fields
            }
        },
    ]

    # Combine all categories
    th_items = cat1_th + cat2_th + cat3_th + cat4_th + cat5_th + cat6_th + cat7_th + cat8_th
    gl_items = cat1_gl + cat2_gl + cat3_gl + cat4_gl + cat5_gl + cat6_gl + cat7_gl + cat8_gl

    assert len(th_items) == 34, f"Expected 34 TruffleHog items, got {len(th_items)}"
    assert len(gl_items) == 34, f"Expected 34 Gitleaks items, got {len(gl_items)}"
    assert len(th_items) + len(gl_items) == 68, "Expected exactly 68 total items!"

    # Write TruffleHog JSONL file
    th_file = DATASET_DIR / "trufflehog_fixtures.jsonl"
    th_lines = []
    for item in th_items:
        if item.get("is_malformed_raw_line"):
            th_lines.append(item["is_malformed_raw_line"])
        else:
            th_lines.append(json.dumps(item["th_record"]))
    th_file.write_text("\n".join(th_lines), encoding="utf-8")

    # Write Gitleaks JSON array file
    gl_file = DATASET_DIR / "gitleaks_fixtures.json"
    gl_array = [item["gl_record"] for item in gl_items]
    gl_file.write_text(json.dumps(gl_array, indent=2), encoding="utf-8")

    # Build ground truth metadata
    ground_truth = []
    for item in (th_items + gl_items):
        meta = {
            "id": item["id"],
            "scanner": "trufflehog" if "th_record" in item or "is_malformed_raw_line" in item else "gitleaks",
            "category": item["category"],
            "expected_classification": item["expected_classification"],
            "expected_priority": item["expected_priority"],
            "asset_scope": item["asset_scope"],
        }
        ground_truth.append(meta)

    gt_file = DATASET_DIR / "ground_truth.json"
    gt_file.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    print(f"Generated {len(ground_truth)} fixtures successfully.")


if __name__ == "__main__":
    create_fixtures()
