import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .file_info import FileTypeInfo, file_type_info_to_tag
from .magic_recognizer import MagicFromBufferFunction, load_magic, recognize_with_magic
from .yara_recognizer import load_yara_rules, recognize_with_yara


def classify_content(
    content: bytes,
    file_name: str,
    magic_fn: MagicFromBufferFunction,
    yara_rules: Any,
) -> tuple[list[FileTypeInfo], str, str]:
    file_types: list[FileTypeInfo] = []

    if yara_rules:
        file_types += recognize_with_yara(content, yara_rules)

    magic, mime = magic_fn(content)

    filemagic_classification = recognize_with_magic(content, file_name, magic, mime)
    if filemagic_classification:
        file_types.append(filemagic_classification)

    return file_types, magic, mime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="karton-classifier-cli",
        description=(
            "Test classification on one or more files in exactly the same "
            "way as it is handled by the Karton Classifier service."
        ),
    )
    parser.add_argument("files", nargs="+", help="Files to classify")
    parser.add_argument(
        "--yara-rules",
        default=None,
        help="Directory containing classifier YARA rules",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit a single JSON array document instead of human-readable output",
    )
    args = parser.parse_args(argv)

    magic_fn = load_magic()

    yara_rules = None
    if args.yara_rules:
        try:
            yara_rules = load_yara_rules(Path(args.yara_rules))
        except (NotADirectoryError, RuntimeError) as exc:
            print(f"Error loading YARA rules: {exc}", file=sys.stderr)
            return 2

    results: list[dict[str, Any]] = []
    exit_code = 0

    for file_path in args.files:
        result: dict[str, Any] = {"file": file_path}
        try:
            content = Path(file_path).read_bytes()
        except OSError as exc:
            result["error"] = str(exc)
            results.append(result)
            exit_code = 1
            continue

        file_types, magic, mime = classify_content(
            content, file_path, magic_fn, yara_rules
        )
        tags = [file_type_info_to_tag(ft) for ft in file_types]

        result["magic"] = magic
        result["mime"] = mime
        result["recognized"] = bool(file_types)
        result["file_types"] = file_types
        result["tags"] = tags
        results.append(result)

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"file: {result['file']}")
            if "error" in result:
                print(f"error: {result['error']}")
                print()
                continue
            print(f"magic: {result['magic']}")
            print(f"mime: {result['mime']}")
            print(f"recognized: {'true' if result['recognized'] else 'false'}")
            print("file_types:")
            for file_type in result["file_types"]:
                print(f"  - {json.dumps(file_type)}")
            print("tags:")
            for tag in result["tags"]:
                print(f"  - {tag}")
            print()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
