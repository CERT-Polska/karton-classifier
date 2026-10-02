import argparse
from hashlib import sha256
from pathlib import Path
from typing import cast

from karton.core import Config, Karton, Task
from karton.core.backend import KartonBackend

from .__version__ import __version__
from .file_info import FileTypeInfo, file_type_info_to_tag
from .magic_recognizer import MagicFromBufferFunction, load_magic, recognize_with_magic
from .yara_recognizer import load_yara_rules, recognize_with_yara


class Classifier(Karton):
    """
    File type classifier for the Karton framework.

    Entrypoint for samples. Classifies type of samples labeled as `kind: raw`,
    which makes them available for subsystems that receive samples with specific
    type only (e.g. `raw` => `runnable:win32:exe`)
    """

    identity = "karton.classifier"
    version = __version__
    filters = [
        {"type": "sample", "kind": "raw"},
    ]

    def __init__(
        self,
        config: Config | None = None,
        identity: str | None = None,
        backend: KartonBackend | None = None,
        magic: MagicFromBufferFunction | None = None,
    ) -> None:
        super().__init__(config=config, identity=identity, backend=backend)
        self._magic = magic or load_magic()

        yara_directory = self.config.get("classifier", "yara_rules", fallback=None)
        if yara_directory:
            yara_p = Path(yara_directory)
            self.yara_rules = load_yara_rules(yara_p)
        else:
            self.yara_rules = None

    @classmethod
    def args_parser(cls) -> argparse.ArgumentParser:
        parser = super().args_parser()
        parser.add_argument(
            "--yara-rules",
            default=None,
            help="Directory containing classifier YARA rules",
        )
        return parser

    @classmethod
    def config_from_args(cls, config: Config, args: argparse.Namespace) -> None:
        super().config_from_args(config, args)
        config.load_from_dict(
            {
                "classifier": {"yara_rules": args.yara_rules},
            }
        )

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        content = cast(bytes, sample.content)
        file_name = sample.name or "sample"

        file_types: list[FileTypeInfo] = []

        if self.yara_rules:
            file_types += recognize_with_yara(content, self.yara_rules)

        magic, mime = self._magic(content)

        filemagic_classification = recognize_with_magic(content, file_name, magic, mime)
        if filemagic_classification:
            file_types.append(filemagic_classification)

        if not file_types:
            self.log.info(
                "Sample {} (sha256: {}) not recognized (unsupported type)".format(
                    file_name, sample.sha256
                )
            )

            res = task.derive_task(
                {
                    "type": "sample",
                    "stage": "unrecognized",
                    "kind": "unknown",
                    "quality": task.headers.get("quality", "high"),
                }
            )
            self.send_task(res)
            return

        for file_type in file_types:
            classification_tag = file_type_info_to_tag(file_type)
            self.log.info(
                "Classified %r as %r and tag %s",
                file_name.encode("utf8"),
                file_type,
                classification_tag,
            )

            derived_headers = {
                "type": "sample",
                "stage": "recognized",
                "kind": file_type["kind"],
                "quality": task.headers.get("quality", "high"),
                "mime": mime,
            }
            if file_type.get("platform") is not None:
                derived_headers["platform"] = file_type["platform"]
            if file_type.get("extension") is not None:
                derived_headers["extension"] = file_type["extension"]
            if file_type.get("rule_name") is not None:
                derived_headers["rule-name"] = file_type["rule_name"]

            derived_task = task.derive_task(derived_headers)
            derived_task.add_payload("magic", magic)

            # pass the original tags to the next task
            tags = [classification_tag]
            if derived_task.has_payload("tags"):
                tags += derived_task.get_payload("tags")
                derived_task.remove_payload("tags")

            derived_task.add_payload("tags", tags)

            # add a sha256 digest in the outgoing task if there
            # isn't one in the incoming task
            if "sha256" not in derived_task.payload["sample"].metadata:
                derived_task.payload["sample"].metadata["sha256"] = sha256(
                    cast(bytes, sample.content)
                ).hexdigest()

            self.send_task(derived_task)
