"""Target parsing and resolution for tria.ge URLs and hashes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import ClassVar


@dataclass(frozen=True)
class Target:
    """Base class for targets."""

    pass


@dataclass(frozen=True)
class HashTarget(Target):
    """A hash-based target.

    Attributes:
        hash_value: The hash string
        hash_type: The type of hash (MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH)
    """

    hash_value: str
    hash_type: str


@dataclass(frozen=True)
class SubmissionTarget(Target):
    """A submission URL target.

    Attributes:
        submission_id: The submission ID (e.g., "260206-mrmcdshv5h")
    """

    submission_id: str


@dataclass(frozen=True)
class AnalysisTarget(Target):
    """An analysis URL target.

    Attributes:
        submission_id: The submission ID
        analysis_name: The analysis name (e.g., "behavioral1")
    """

    submission_id: str
    analysis_name: str


class TargetParser:
    """Parser for tria.ge targets."""

    # URL patterns
    TRIAGE_URL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^https?://tria\.ge/([^/]+)(?:/([^/]+))?/?$"
    )

    # Hash patterns: (expected_length_or_0, regex)
    HASH_PATTERNS: ClassVar[dict[str, tuple[int, re.Pattern[str]]]] = {
        "MD5": (32, re.compile(r"^[a-fA-F0-9]{32}$")),
        "SHA1": (40, re.compile(r"^[a-fA-F0-9]{40}$")),
        "SHA256": (64, re.compile(r"^[a-fA-F0-9]{64}$")),
        "SHA512": (128, re.compile(r"^[a-fA-F0-9]{128}$")),
        "SSDEEP": (0, re.compile(r"^\d+:[a-zA-Z0-9+/]+:[a-zA-Z0-9+/]+$")),
        "TLSH": (0, re.compile(r"^T[0-9A-F]{71}$")),
    }

    # Hex hash types that should be lowercased
    _HEX_HASHES: ClassVar[frozenset[str]] = frozenset({"MD5", "SHA1", "SHA256", "SHA512"})

    @classmethod
    def parse(cls, target: str) -> HashTarget | SubmissionTarget | AnalysisTarget:
        """Parse a target string into a Target object.

        Args:
            target: The target string (URL or hash)

        Returns:
            A Target subclass instance

        Raises:
            ValueError: If the target cannot be parsed
        """
        target = target.strip()

        # Try URL parsing first
        if target.startswith("http://") or target.startswith("https://"):
            try:
                return cls._parse_url(target)
            except ValueError:
                # URL parsing failed, continue to try hash parsing
                pass

        # Try hash parsing
        hash_target = cls._parse_hash(target)
        if hash_target:
            return hash_target

        raise ValueError(f"Unable to parse target: {target}")

    @classmethod
    def _parse_url(cls, url: str) -> SubmissionTarget | AnalysisTarget:
        """Parse a tria.ge URL."""
        match = cls.TRIAGE_URL_PATTERN.match(url)
        if not match:
            raise ValueError(f"Invalid tria.ge URL: {url}")

        submission_id = match.group(1)
        analysis_name = match.group(2)

        if analysis_name:
            return AnalysisTarget(submission_id, analysis_name)
        return SubmissionTarget(submission_id)

    @classmethod
    def _parse_hash(cls, hash_value: str) -> HashTarget | None:
        """Parse a hash string.

        Args:
            hash_value: The hash string to parse

        Returns:
            HashTarget if valid hash, None otherwise
        """
        hash_value = hash_value.strip()

        for hash_type, (_length, pattern) in cls.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                normalized = hash_value.lower() if hash_type in cls._HEX_HASHES else hash_value
                return HashTarget(normalized, hash_type)

        return None

    @classmethod
    def detect_hash_type(cls, hash_value: str) -> str | None:
        """Detect the type of a hash.

        Args:
            hash_value: The hash string

        Returns:
            Hash type name or None if not a valid hash
        """
        hash_value = hash_value.strip()

        for hash_type, (_length, pattern) in cls.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                return hash_type

        return None
