"""API client for tria.ge malware analysis API."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from triage.config import get_api_key

if TYPE_CHECKING:
    from typing import Any


BASE_URL = "https://api.tria.ge/v0"


class APIError(Exception):
    """Raised when API request fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        if self.status_code:
            return f"API Error ({self.status_code}): {self.message}"
        return f"API Error: {self.message}"


class TriageClient:
    """HTTP client for tria.ge API."""

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize the API client.

        Args:
            api_key: Optional API key. If not provided, will be loaded from config.
        """
        self.api_key = api_key or get_api_key()
        self.client = httpx.Client(
            base_url=BASE_URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=60.0,
        )

    def _handle_error(self, response: httpx.Response) -> None:
        """Handle API error responses."""
        if response.status_code == 401:
            raise APIError("Invalid API key", 401)
        if response.status_code == 404:
            raise APIError("Not found", 404)
        if response.status_code == 429:
            raise APIError("Rate limit exceeded", 429)
        if response.status_code >= 400:
            raise APIError(
                f"Request failed: {response.text}", response.status_code
            )

    def search_by_hash(self, hash_value: str) -> list[dict[str, Any]]:
        """Search for samples by hash.

        Args:
            hash_value: The hash to search for (MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH)

        Returns:
            List of matching submissions
        """
        response = self.client.get("/search", params={"query": hash_value})
        self._handle_error(response)
        data = response.json()
        # API returns {"data": [...], "next": ...} structure
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data if isinstance(data, list) else []

    def get_submission(self, submission_id: str) -> dict[str, Any]:
        """Get submission details.

        Args:
            submission_id: The submission ID

        Returns:
            Submission details
        """
        response = self.client.get(f"/samples/{submission_id}")
        self._handle_error(response)
        return response.json()

    def get_sample_url(self, sample_id: str) -> str:
        """Get the download URL for a sample.

        Args:
            sample_id: The sample ID

        Returns:
            Download URL
        """
        return f"{BASE_URL}/samples/{sample_id}/sample"

    def download_sample(self, sample_id: str, output_path: str) -> None:
        """Download a sample to a file.

        Args:
            sample_id: The sample ID
            output_path: Path to save the file
        """
        url = self.get_sample_url(sample_id)
        with self.client.stream("GET", url) as response:
            self._handle_error(response)
            with open(output_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)

    def get_report(self, submission_id: str, analysis_name: str) -> dict[str, Any]:
        """Get analysis report.

        Args:
            submission_id: The submission ID
            analysis_name: The analysis name (e.g., "behavioral1")

        Returns:
            Analysis report
        """
        response = self.client.get(
            f"/samples/{submission_id}/{analysis_name}/report_triage.json"
        )
        self._handle_error(response)
        return response.json()

    def get_domains(self, submission_id: str, analysis_name: str) -> list[str]:
        """Get contacted domains/URLs from an analysis.

        Args:
            submission_id: The submission ID
            analysis_name: The analysis name

        Returns:
            List of domains/URLs
        """
        report = self.get_report(submission_id, analysis_name)
        domains: set[str] = set()

        # Extract domains from network activity
        network = report.get("network", {})

        # URLs from HTTP requests
        for http in network.get("http", []):
            if "uri" in http:
                domains.add(http["uri"])

        # Domains from DNS requests
        for dns in network.get("dns", []):
            if "hostname" in dns:
                domains.add(dns["hostname"])

        # Domains from connections
        for conn in network.get("connections", []):
            if "dst" in conn:
                domains.add(conn["dst"])

        return sorted(domains)

    def get_dumped_files(self, submission_id: str, analysis_name: str) -> list[dict[str, Any]]:
        """Get list of dumped files from dynamic analysis.

        Args:
            submission_id: The submission ID
            analysis_name: The analysis name

        Returns:
            List of dumped file metadata
        """
        response = self.client.get(
            f"/samples/{submission_id}/{analysis_name}/dumped_files"
        )
        self._handle_error(response)
        return response.json()

    def download_dumped_file(
        self, submission_id: str, analysis_name: str, file_id: str, output_path: str
    ) -> None:
        """Download a dumped file.

        Args:
            submission_id: The submission ID
            analysis_name: The analysis name
            file_id: The file ID
            output_path: Path to save the file
        """
        url = f"{BASE_URL}/samples/{submission_id}/{analysis_name}/dumped_files/{file_id}"
        with self.client.stream("GET", url) as response:
            self._handle_error(response)
            with open(output_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)

    def get_dumped_file_metadata(self, submission_id: str, analysis_name: str, file_id: str) -> dict[str, Any]:
        """Get detailed metadata for a dumped file.

        Args:
            submission_id: The submission ID
            analysis_name: The analysis name
            file_id: The file ID

        Returns:
            Dumped file metadata including original path
        """
        response = self.client.get(
            f"/samples/{submission_id}/{analysis_name}/dumped_files/{file_id}"
        )
        self._handle_error(response)
        return response.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self) -> TriageClient:
        """Context manager entry."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.close()
