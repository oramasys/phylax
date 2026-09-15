"""Phylax redaction tests: sensitive keys and URL queries scrubbed."""

from phylax.redaction import redact_details


def test_sensitive_keys_are_redacted():
    details = {
        "provider_ref": "provider-1",
        "api_key": "sk-live-123",
        "Authorization": "Bearer abc",
        "decision_ref": "telos-decision-1",
    }
    redacted = redact_details(details)

    assert redacted["provider_ref"] == "provider-1"  # non-sensitive passes
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["decision_ref"] == "telos-decision-1"
    assert details["api_key"] == "sk-live-123"  # input never mutated


def test_url_query_strings_are_stripped_but_base_is_kept():
    redacted = redact_details({"resolved_url": "http://127.0.0.1:11434/v1?key=secret"})
    assert redacted["resolved_url"] == "http://127.0.0.1:11434/v1?[REDACTED]"


def test_non_string_values_pass_through():
    redacted = redact_details({"count": 3, "flag": True, "nested": {"a": 1}})
    assert redacted == {"count": 3, "flag": True, "nested": {"a": 1}}
