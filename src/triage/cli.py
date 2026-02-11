"""CLI for tria.ge malware analysis API."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import click

from triage.api import APIError, TriageClient
from triage.config import ConfigError
from triage.target import AnalysisTarget, HashTarget, SubmissionTarget, TargetParser

if TYPE_CHECKING:
    from typing import Any


ZIP_PASSWORD = b"infected"


def disambiguate_filename(filename: str, seen_names: dict[str, int]) -> str:
    """Generate a unique filename by appending a counter if needed.

    Args:
        filename: The desired filename
        seen_names: Dictionary tracking how many times each base name has been used

    Returns:
        A unique filename (original or with counter appended before extension)
    """
    if filename not in seen_names:
        seen_names[filename] = 0
        return filename

    # Increment counter for this filename
    seen_names[filename] += 1
    count = seen_names[filename]

    # Split filename into name and extension
    path = Path(filename)
    stem = path.stem
    suffix = path.suffix

    # Append counter before extension
    return f"{stem}-{count}{suffix}"


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """Triage CLI - Interact with the tria.ge malware analysis API."""
    pass


def resolve_target(
    client: TriageClient, target_str: str
) -> list[tuple[str, str]]:  # (submission_id, analysis_name | "")
    """Resolve a target string to list of (submission_id, analysis_name) tuples.

    Returns:
        List of tuples: (submission_id, analysis_name). analysis_name is empty string
        if target is a submission URL or hash search result.
    """
    parsed = TargetParser.parse(target_str)

    if isinstance(parsed, HashTarget):
        # Search for submissions by hash
        results = client.search_by_hash(parsed.hash_value)
        if not results:
            raise click.ClickException(f"No samples found for hash: {parsed.hash_value}")
        # Return all matching submissions
        return [(r.get("id", ""), "") for r in results if r.get("id")]

    elif isinstance(parsed, AnalysisTarget):
        # Specific analysis
        return [(parsed.submission_id, parsed.analysis_name)]

    elif isinstance(parsed, SubmissionTarget):
        # All analyses in submission
        return [(parsed.submission_id, "")]

    return []


def resolve_output_path(prefix: str | None, filename: str) -> Path:
    """Resolve output path from prefix and filename.

    Args:
        prefix: Optional prefix (directory if ends with /, filename prefix otherwise)
        filename: Default filename

    Returns:
        Resolved Path
    """
    if not prefix:
        return Path(filename)

    # Expand home directory
    prefix = prefix.replace("~", str(Path.home()))

    if prefix.endswith("/"):
        # Directory prefix
        dir_path = Path(prefix)
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path / filename
    else:
        # Filename prefix
        return Path(f"{prefix}-{filename}")


@cli.command()
@click.argument("target")
@click.argument("prefix", required=False)
def sample(target: str, prefix: str | None) -> None:
    """Download a malware sample.

    TARGET: Hash or tria.ge URL
    PREFIX: Optional output prefix (directory if ends with /)
    """
    try:
        with TriageClient() as client:
            parsed = TargetParser.parse(target)

            if isinstance(parsed, HashTarget):
                # Search for sample by hash
                results = client.search_by_hash(parsed.hash_value)
                if not results:
                    raise click.ClickException(
                        f"No samples found for hash: {parsed.hash_value}"
                    )

                # Get first matching submission
                submission = results[0]
                sample_id = submission.get("id")
                if not sample_id:
                    raise click.ClickException("Invalid response from API")

            elif isinstance(parsed, (SubmissionTarget, AnalysisTarget)):
                # Get sample from submission
                submission_id = parsed.submission_id
                submission_data = client.get_submission(submission_id)
                sample_id = submission_data.get("id")
                if not sample_id:
                    raise click.ClickException("No sample found in submission")
            else:
                raise click.ClickException(f"Invalid target: {target}")

            # Download sample as ZIP
            zip_filename = f"{sample_id}.zip"
            output_zip = resolve_output_path(prefix, zip_filename)

            click.echo(f"Downloading sample {sample_id}...")
            client.download_sample(sample_id, str(output_zip))

            # Extract and remove ZIP
            extract_dir = output_zip.parent
            with zipfile.ZipFile(output_zip, "r") as zf:
                zf.extractall(extract_dir, pwd=ZIP_PASSWORD)

            output_zip.unlink()

            # Find extracted file (should be the sample)
            extracted_files = list(extract_dir.iterdir())
            sample_file = None
            for f in extracted_files:
                if f.name != zip_filename and f.is_file():
                    sample_file = f
                    break

            if sample_file:
                click.echo(f"Sample saved to: {sample_file}")
            else:
                click.echo(f"Sample extracted to: {extract_dir}")

    except ConfigError as e:
        raise click.ClickException(str(e))
    except APIError as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("target")
@click.argument("prefix", required=False)
def domains(target: str, prefix: str | None) -> None:
    """Download contacted domains/URLs from analysis.

    TARGET: Hash or tria.ge URL
    PREFIX: Optional output prefix (directory if ends with /)
    """
    try:
        with TriageClient() as client:
            parsed = TargetParser.parse(target)

            all_domains: set[str] = set()

            if isinstance(parsed, HashTarget):
                # Search for submissions by hash
                results = client.search_by_hash(parsed.hash_value)
                if not results:
                    raise click.ClickException(
                        f"No samples found for hash: {parsed.hash_value}"
                    )

                # Collect domains from all analyses
                for submission in results:
                    submission_id = submission.get("id")
                    if not submission_id:
                        continue

                    submission_data = client.get_submission(submission_id)
                    analyses = submission_data.get("analyses", [])

                    for analysis in analyses:
                        analysis_name = analysis.get("name", "")
                        if analysis_name:
                            try:
                                domains = client.get_domains(submission_id, analysis_name)
                                all_domains.update(domains)
                            except APIError:
                                # Skip analyses without reports
                                pass

            elif isinstance(parsed, AnalysisTarget):
                # Single analysis
                domains = client.get_domains(parsed.submission_id, parsed.analysis_name)
                all_domains.update(domains)

            elif isinstance(parsed, SubmissionTarget):
                # All analyses in submission
                submission_data = client.get_submission(parsed.submission_id)
                analyses = submission_data.get("analyses", [])

                for analysis in analyses:
                    analysis_name = analysis.get("name", "")
                    if analysis_name:
                        try:
                            domains = client.get_domains(
                                parsed.submission_id, analysis_name
                            )
                            all_domains.update(domains)
                        except APIError:
                            # Skip analyses without reports
                            pass

            if not all_domains:
                click.echo("No domains found.")
                return

            # Write output
            output_path = resolve_output_path(prefix, "domains.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                for domain in sorted(all_domains):
                    f.write(f"{domain}\n")

            click.echo(f"Domains saved to: {output_path}")

    except ConfigError as e:
        raise click.ClickException(str(e))
    except APIError as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("target")
@click.argument("prefix", required=False)
def dumps(target: str, prefix: str | None) -> None:
    """Download dumped files from dynamic analysis.

    TARGET: Hash or tria.ge URL
    PREFIX: Optional output prefix (directory if ends with /)
    """
    try:
        with TriageClient() as client:
            parsed = TargetParser.parse(target)

            files_to_download: list[tuple[str, str, str, str]] = (
                []
            )  # (submission_id, analysis_name, file_name, filename)

            if isinstance(parsed, HashTarget):
                # Search for submissions by hash
                results = client.search_by_hash(parsed.hash_value)
                if not results:
                    raise click.ClickException(
                        f"No samples found for hash: {parsed.hash_value}"
                    )

                # Collect dumped files from all analyses
                for submission in results:
                    submission_id = submission.get("id")
                    if not submission_id:
                        continue

                    submission_data = client.get_submission(submission_id)
                    analyses = submission_data.get("analyses", [])

                    for analysis in analyses:
                        analysis_name = analysis.get("name", "")
                        if analysis_name:
                            try:
                                dumped = client.get_dumped_files(
                                    submission_id, analysis_name
                                )
                                for f in dumped:
                                    file_name = f.get("name", "")
                                    if file_name:
                                        files_to_download.append(
                                            (
                                                submission_id,
                                                analysis_name,
                                                file_name,
                                                f.get("filename", file_name),
                                            )
                                        )
                            except APIError:
                                pass

            elif isinstance(parsed, AnalysisTarget):
                # Single analysis
                dumped = client.get_dumped_files(parsed.submission_id, parsed.analysis_name)
                for f in dumped:
                    file_name = f.get("name", "")
                    if file_name:
                        files_to_download.append(
                            (
                                parsed.submission_id,
                                parsed.analysis_name,
                                file_name,
                                f.get("filename", file_name),
                            )
                        )

            elif isinstance(parsed, SubmissionTarget):
                # All analyses in submission
                submission_data = client.get_submission(parsed.submission_id)
                analyses = submission_data.get("analyses", [])

                for analysis in analyses:
                    analysis_name = analysis.get("name", "")
                    if analysis_name:
                        try:
                            dumped = client.get_dumped_files(
                                parsed.submission_id, analysis_name
                            )
                            for f in dumped:
                                file_name = f.get("name", "")
                                if file_name:
                                    files_to_download.append(
                                        (
                                            parsed.submission_id,
                                            analysis_name,
                                            file_name,
                                            f.get("filename", file_name),
                                        )
                                    )
                        except APIError:
                            pass

            if not files_to_download:
                click.echo("No dumped files found.")
                return

            # Determine output directory
            if prefix and prefix.endswith("/"):
                output_dir = Path(prefix.replace("~", str(Path.home())))
            elif prefix:
                output_dir = Path(".")
            else:
                output_dir = Path(".")

            output_dir.mkdir(parents=True, exist_ok=True)

            # Download files with unique names
            downloaded: list[Path] = []
            seen_names: dict[str, int] = {}
            for submission_id, analysis_name, file_name, filename in files_to_download:
                # Sanitize filename to avoid path issues (e.g., "files/fstream-1.dat")
                safe_filename = filename.replace("/", "-")
                # Disambiguate filename to handle duplicates
                unique_filename = disambiguate_filename(safe_filename, seen_names)
                if prefix and not prefix.endswith("/"):
                    # Add prefix to filename
                    output_filename = f"{prefix}-{submission_id}-{analysis_name}-{unique_filename}"
                else:
                    output_filename = f"{submission_id}-{analysis_name}-{unique_filename}"

                output_path = output_dir / output_filename
                client.download_dumped_file(submission_id, analysis_name, file_name, str(output_path))
                downloaded.append(output_path)

            click.echo(f"Downloaded {len(downloaded)} files to: {output_dir}")

    except ConfigError as e:
        raise click.ClickException(str(e))
    except APIError as e:
        raise click.ClickException(str(e))


def main() -> None:
    """Entry point for the CLI."""
    cli()
