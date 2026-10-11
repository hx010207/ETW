import json
import os
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from etw.models.observation import Observation

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_RECORD_SIZE_BYTES = 64 * 1024       # 64 KB


class IngestError(BaseModel):
    record_index: int
    error_code: str
    message: str
    line_number: Optional[int] = None


class IngestResult(BaseModel):
    observations: List[Observation] = Field(default_factory=list)
    errors: List[IngestError] = Field(default_factory=list)
    total_read: int = 0
    successful_count: int = 0
    quarantined_count: int = 0


def validate_file_size(file_path: Union[str, Path]) -> None:
    """Ensure file size is within bounded limits."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"Input file ({size} bytes) exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES} bytes."
        )


def iter_json_records(
    file_path: Union[str, Path]
) -> Iterator[Tuple[int, Optional[dict], Optional[IngestError]]]:
    """Stream JSON records from either a JSONL file or a standard JSON array.
    
    Yields (index, dict_or_none, error_or_none).
    Bounded memory: JSONL files are streamed line-by-line.
    """
    validate_file_size(file_path)
    path = Path(file_path)

    if path.stat().st_size == 0:
        return

    # Inspect first non-whitespace character to distinguish array vs JSONL
    first_char = ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for chunk in iter(lambda: f.read(1024), ""):
            stripped = chunk.strip()
            if stripped:
                first_char = stripped[0]
                break

    if first_char == "[":
        # Standard JSON array
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            yield (
                0,
                None,
                IngestError(
                    record_index=0,
                    error_code="JSON_DECODE_ERROR",
                    message=f"Failed to parse JSON array: {str(exc)}",
                ),
            )
            return

        if not isinstance(data, list):
            yield (
                0,
                None,
                IngestError(
                    record_index=0,
                    error_code="INVALID_ROOT_TYPE",
                    message=f"Expected JSON list at root, got {type(data).__name__}",
                ),
            )
            return

        for idx, item in enumerate(data):
            if isinstance(item, dict):
                yield (idx, item, None)
            else:
                yield (
                    idx,
                    None,
                    IngestError(
                        record_index=idx,
                        error_code="INVALID_RECORD_TYPE",
                        message=f"Record {idx} is not a JSON object",
                    ),
                )
    else:
        # JSONL format: read line-by-line
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue

                if len(line.encode("utf-8")) > MAX_RECORD_SIZE_BYTES:
                    yield (
                        idx,
                        None,
                        IngestError(
                            record_index=idx,
                            line_number=idx + 1,
                            error_code="RECORD_TOO_LARGE",
                            message=f"Line {idx + 1} exceeds maximum size of {MAX_RECORD_SIZE_BYTES} bytes",
                        ),
                    )
                    continue

                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, dict):
                        yield (idx, parsed, None)
                    else:
                        yield (
                            idx,
                            None,
                            IngestError(
                                record_index=idx,
                                line_number=idx + 1,
                                error_code="INVALID_RECORD_TYPE",
                                message=f"Line {idx + 1} is not a JSON object",
                            ),
                        )
                except json.JSONDecodeError as exc:
                    yield (
                        idx,
                        None,
                        IngestError(
                            record_index=idx,
                            line_number=idx + 1,
                            error_code="JSON_DECODE_ERROR",
                            message=f"Line {idx + 1} contains malformed JSON",
                        ),
                    )
