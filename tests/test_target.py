"""Tests for target parsing."""

import pytest

from triage.target import (
    AnalysisTarget,
    HashTarget,
    SubmissionTarget,
    TargetParser,
)


class TestHashParsing:
    """Test hash detection and parsing."""

    def test_md5(self):
        hash_value = "bf458fab974aa1888eb064082711cd8c"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "MD5"

    def test_sha1(self):
        hash_value = "16a75d57993c1591d6b52a8740ca85768a13ab49"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "SHA1"

    def test_sha256(self):
        hash_value = "318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "SHA256"

    def test_sha512(self):
        hash_value = (
            "7dfe0089a4d7de8ed35f667523bfacefc713a66a976ee16f9398df21c7c15d67"
            "6e12e7ac71b1560990f61a43bcb0d4f882bae52bf6e9597ff2da5e64bce4bc20"
        )
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "SHA512"

    def test_ssdeep(self):
        hash_value = "98304:0utyj7T/GBqO7KAP4I0qIKXh6V+F3OK12tAC7zjZRFJ+YvX:14rWf7lgI0qJU+FIzj7FJF"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "SSDEEP"

    def test_tlsh(self):
        hash_value = "T13416237AFF8DE43AD023E439D164A8438818415C8514FF672B25A75C8EEAC819367FED"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value
        assert result.hash_type == "TLSH"

    def test_uppercase_hash_normalized(self):
        """Test that hex hashes are normalized to lowercase."""
        hash_value = "BF458FAB974AA1888EB064082711CD8C"
        result = TargetParser.parse(hash_value)
        assert isinstance(result, HashTarget)
        assert result.hash_value == hash_value.lower()

    def test_invalid_hash(self):
        """Test that invalid hash raises ValueError."""
        with pytest.raises(ValueError, match="Unable to parse target"):
            TargetParser.parse("not_a_hash")


class TestURLParsing:
    """Test tria.ge URL parsing."""

    def test_submission_url(self):
        url = "https://tria.ge/260206-mrmcdshv5h/"
        result = TargetParser.parse(url)
        assert isinstance(result, SubmissionTarget)
        assert result.submission_id == "260206-mrmcdshv5h"

    def test_submission_url_no_trailing_slash(self):
        url = "https://tria.ge/260206-mrmcdshv5h"
        result = TargetParser.parse(url)
        assert isinstance(result, SubmissionTarget)
        assert result.submission_id == "260206-mrmcdshv5h"

    def test_analysis_url(self):
        url = "https://tria.ge/260206-mrmcdshv5h/behavioral1"
        result = TargetParser.parse(url)
        assert isinstance(result, AnalysisTarget)
        assert result.submission_id == "260206-mrmcdshv5h"
        assert result.analysis_name == "behavioral1"

    def test_analysis_url_trailing_slash(self):
        url = "https://tria.ge/260206-mrmcdshv5h/behavioral1/"
        result = TargetParser.parse(url)
        assert isinstance(result, AnalysisTarget)
        assert result.submission_id == "260206-mrmcdshv5h"
        assert result.analysis_name == "behavioral1"

    def test_http_url(self):
        """Test that http:// URLs are also accepted."""
        url = "http://tria.ge/260206-mrmcdshv5h/behavioral1"
        result = TargetParser.parse(url)
        assert isinstance(result, AnalysisTarget)
        assert result.submission_id == "260206-mrmcdshv5h"

    def test_invalid_url(self):
        """Test that non-triage URLs raise ValueError."""
        with pytest.raises(ValueError, match="Unable to parse target"):
            TargetParser.parse("https://example.com/something")


class TestHashDetection:
    """Test hash type detection."""

    def test_detect_md5(self):
        assert TargetParser.detect_hash_type("bf458fab974aa1888eb064082711cd8c") == "MD5"

    def test_detect_sha1(self):
        assert (
            TargetParser.detect_hash_type("16a75d57993c1591d6b52a8740ca85768a13ab49")
            == "SHA1"
        )

    def test_detect_none(self):
        assert TargetParser.detect_hash_type("not_a_hash") is None
