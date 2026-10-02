import logging
from pathlib import Path

import yara  # type: ignore

from karton.classifier.file_info import FileTypeInfo

# Karton logger name is the same as Karton identity
logger = logging.getLogger("karton.classifier")


def load_yara_rules(path: Path) -> yara.Rules:
    if not path.is_dir():
        raise NotADirectoryError(path)

    rule_files = {}
    for f in path.glob("*.yar"):
        rule_files[f.name] = f.as_posix()

    rules = yara.compile(filepaths=rule_files)
    for r in rules:
        if not r.meta.get("kind"):
            raise RuntimeError(
                f"Rule {r.identifier} does not have a `kind` meta attribute"
            )

    logger.info("Loaded %d yara classifier rules", len(list(rules)))
    return rules


def recognize_with_yara(
    content: bytes,
    yara_rules: yara.Rules,
) -> list[FileTypeInfo]:
    sample_classes: list[FileTypeInfo] = []
    yara_matches = yara_rules.match(data=content)
    for match in yara_matches:
        sample_class: FileTypeInfo = {
            "rule_name": match.rule,
            "kind": match.meta["kind"],
        }
        if match.meta.get("platform"):
            sample_class["platform"] = match.meta["platform"]
        if match.meta.get("extension"):
            sample_class["extension"] = match.meta["extension"]

        logger.info("Matched the sample using Yara rule %s", match.rule)
        sample_classes.append(sample_class)

    return sample_classes
