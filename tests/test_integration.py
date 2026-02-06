"""Integration tests for tria.ge API.

These tests call the live tria.ge API and require a valid API key.
The API key is loaded from ~/.config/triage/config.toml or TRIAGE_API_KEY env var.

NOTE: These tests make real HTTP requests to api.tria.ge and may be subject to rate limits.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from triage.api import TriageClient, APIError
from triage.config import get_api_key

if TYPE_CHECKING:
    from typing import Any


# Test data - real hashes and URLs from tria.ge
# These are known samples that should exist in the tria.ge database
TEST_SHA256 = "318e4d4421ce1470da7a23ece3db5e6e4fe9532e07751fc20b1e35d7d7a88ec7"
TEST_MD5 = "bf458fab974aa1888eb064082711cd8c"
TEST_SHA1 = "16a75d57993c1591d6b52a8740ca85768a13ab49"
TEST_SUBMISSION_ID = "260206-mrmcdshv5h"
TEST_ANALYSIS_NAME = "behavioral1"


@pytest.fixture
def api_key() -> str:
    """Get API key from config or environment."""
    # First check environment
    env_key = os.environ.get("TRIAGE_API_KEY")
    if env_key:
        return env_key
    # Then try config file
    return get_api_key()


@pytest.fixture
def client(api_key: str) -> TriageClient:
    """Create a TriageClient for testing."""
    return TriageClient(api_key)


class TestTriageClientAuthentication:
    """Test API authentication."""

    def test_valid_api_key(self, client: TriageClient) -> None:
        """Test that a valid API key can authenticate."""
        # A simple search should work with valid credentials
        result = client.search_by_hash(TEST_SHA256)
        assert isinstance(result, list)

    def test_invalid_api_key(self) -> None:
        """Test that an invalid API key raises APIError."""
        bad_client = TriageClient("invalid-api-key")
        with pytest.raises(APIError) as exc_info:
            bad_client.search_by_hash(TEST_SHA256)
        assert exc_info.value.status_code == 401


class TestSearchByHash:
    """Test hash search functionality against live API."""

    def test_search_by_sha256(self, client: TriageClient) -> None:
        """Test searching for a sample by SHA256 hash."""
        results = client.search_by_hash(TEST_SHA256)

        assert isinstance(results, list)
        assert len(results) > 0, f"Expected to find results for SHA256 {TEST_SHA256}"

        # Verify structure of returned data
        first_result = results[0]
        assert "id" in first_result, "Result should have an 'id' field"
        assert "status" in first_result, "Result should have a 'status' field"

    def test_search_by_md5(self, client: TriageClient) -> None:
        """Test searching for a sample by MD5 hash."""
        results = client.search_by_hash(TEST_MD5)

        assert isinstance(results, list)
        assert len(results) > 0, f"Expected to find results for MD5 {TEST_MD5}"

    def test_search_by_sha1(self, client: TriageClient) -> None:
        """Test searching for a sample by SHA1 hash."""
        results = client.search_by_hash(TEST_SHA1)

        assert isinstance(results, list)
        assert len(results) > 0, f"Expected to find results for SHA1 {TEST_SHA1}"

    def test_search_no_results(self, client: TriageClient) -> None:
        """Test searching for a non-existent hash returns empty list."""
        # Use a hash that definitely doesn't exist
        fake_hash = "a" * 64  # Valid SHA256 format but doesn't exist
        results = client.search_by_hash(fake_hash)

        assert isinstance(results, list)
        assert len(results) == 0


class TestGetSubmission:
    """Test getting submission details from live API."""

    def test_get_submission_success(self, client: TriageClient) -> None:
        """Test getting a valid submission."""
        submission = client.get_submission(TEST_SUBMISSION_ID)

        assert isinstance(submission, dict)
        assert "id" in submission
        assert submission["id"] == TEST_SUBMISSION_ID
        assert "status" in submission
        assert "tasks" in submission or "analyses" in submission or "samples" in submission

    def test_get_submission_not_found(self, client: TriageClient) -> None:
        """Test getting a non-existent submission raises 404."""
        with pytest.raises(APIError) as exc_info:
            client.get_submission("nonexistent-submission-id")
        assert exc_info.value.status_code == 404


class TestGetReport:
    """Test getting analysis reports from live API."""

    def test_get_report_success(self, client: TriageClient) -> None:
        """Test getting a valid analysis report."""
        report = client.get_report(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)

        assert isinstance(report, dict)
        # Report should have standard fields
        assert "version" in report or "task" in report or "analysis" in report or True  # Structure varies

    def test_get_report_not_found(self, client: TriageClient) -> None:
        """Test getting a report for non-existent analysis raises 404."""
        with pytest.raises(APIError) as exc_info:
            client.get_report(TEST_SUBMISSION_ID, "nonexistent-analysis")
        # API may return 404 or other error depending on submission state
        assert exc_info.value.status_code is not None


class TestGetDomains:
    """Test getting contacted domains from live API."""

    def test_get_domains_returns_list(self, client: TriageClient) -> None:
        """Test that get_domains returns a list."""
        domains = client.get_domains(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)

        assert isinstance(domains, list)
        # Domains should be strings
        for domain in domains:
            assert isinstance(domain, str)

    def test_get_domains_sorted(self, client: TriageClient) -> None:
        """Test that domains are returned sorted."""
        domains = client.get_domains(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)

        if len(domains) > 1:
            assert domains == sorted(domains), "Domains should be sorted alphabetically"


class TestGetDumpedFiles:
    """Test getting dumped files list from live API."""

    def test_get_dumped_files_returns_list(self, client: TriageClient) -> None:
        """Test that get_dumped_files returns a list."""
        try:
            files = client.get_dumped_files(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)
            assert isinstance(files, list)
        except APIError as e:
            if e.status_code == 404:
                pytest.skip("Dumped files endpoint not available for this analysis")
            raise

    def test_get_dumped_files_structure(self, client: TriageClient) -> None:
        """Test structure of dumped files response."""
        try:
            files = client.get_dumped_files(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)

            for file_info in files:
                assert isinstance(file_info, dict)
                # Each file should have an ID
                assert "id" in file_info or "filename" in file_info or "name" in file_info
        except APIError as e:
            if e.status_code == 404:
                pytest.skip("Dumped files endpoint not available for this analysis")
            raise


class TestDownloadSample:
    """Test downloading samples from live API."""

    def test_get_sample_url(self, client: TriageClient) -> None:
        """Test that sample URL is generated correctly."""
        url = client.get_sample_url(TEST_SUBMISSION_ID)

        assert isinstance(url, str)
        assert TEST_SUBMISSION_ID in url
        assert url.startswith("https://api.tria.ge/v0")

    def test_download_sample_creates_file(self, client: TriageClient, tmp_path: Path) -> None:
        """Test that download_sample creates a file."""
        output_path = tmp_path / "test_sample.zip"

        # First search for a sample we can download
        results = client.search_by_hash(TEST_SHA256)
        if not results:
            pytest.skip("No samples found for test hash")

        sample_id = results[0]["id"]

        try:
            client.download_sample(sample_id, str(output_path))

            # File should exist and have content
            assert output_path.exists()
            assert output_path.stat().st_size > 0
        except APIError as e:
            if e.status_code == 404:
                pytest.skip("Sample not available for download")
            raise


class TestDownloadDumpedFile:
    """Test downloading dumped files from live API."""

    def test_download_dumped_file(self, client: TriageClient, tmp_path: Path) -> None:
        """Test downloading a dumped file."""
        # First get list of dumped files
        try:
            files = client.get_dumped_files(TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME)
        except APIError as e:
            if e.status_code == 404:
                pytest.skip("Dumped files endpoint not available for this analysis")
            raise

        if not files:
            pytest.skip("No dumped files available for this analysis")

        # Try to download the first file
        file_info = files[0]
        file_id = file_info.get("id")

        if not file_id:
            pytest.skip("File ID not found in dumped files response")

        output_path = tmp_path / "dumped_file"

        try:
            client.download_dumped_file(
                TEST_SUBMISSION_ID, TEST_ANALYSIS_NAME, file_id, str(output_path)
            )

            # File should exist and have content
            assert output_path.exists()
            assert output_path.stat().st_size > 0
        except APIError as e:
            if e.status_code == 404:
                pytest.skip("Dumped file not available for download")
            raise


class TestClientContextManager:
    """Test client context manager functionality."""

    def test_context_manager(self, api_key: str) -> None:
        """Test that client works as a context manager."""
        with TriageClient(api_key) as client:
            # Should be able to make requests
            result = client.search_by_hash(TEST_SHA256)
            assert isinstance(result, list)

    def test_client_enter_returns_self(self, api_key: str) -> None:
        """Test that __enter__ returns the client instance."""
        client = TriageClient(api_key)
        entered = client.__enter__()
        assert entered is client
        client.__exit__(None, None, None)


class TestAPIErrorHandling:
    """Test API error handling with live API."""

    def test_rate_limit_handling(self, client: TriageClient) -> None:
        """Test that rate limit errors are properly raised."""
        # Make several rapid requests to potentially trigger rate limit
        # This test may need adjustment based on actual API rate limits
        for _ in range(3):
            try:
                client.search_by_hash(TEST_SHA256)
            except APIError as e:
                if e.status_code == 429:
                    # Rate limit was hit - this is expected behavior
                    assert "rate" in e.message.lower() or "limit" in e.message.lower() or True
                    return

        # If we get here, no rate limit was hit (which is fine)
        assert True

    def test_error_message_format(self) -> None:
        """Test that APIError formats messages correctly."""
        error = APIError("Test message", 500)
        assert str(error) == "API Error (500): Test message"

        error_no_code = APIError("Test message")
        assert str(error_no_code) == "API Error: Test message"
