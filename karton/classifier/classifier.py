import re
import struct
from hashlib import sha256
from io import BytesIO
from typing import Dict, Optional
from zipfile import ZipFile

import chardet  # type: ignore
import magic as pymagic  # type: ignore
from karton.core import Karton, Resource  # type: ignore

from .__version__ import __version__


def classify_openxml(content: bytes) -> Optional[str]:
    zipfile = ZipFile(BytesIO(content))
    extensions = {"docx": "word/", "pptx": "ppt/", "xlsx": "xl/"}
    filenames = [x.filename for x in zipfile.filelist]

    for ext, file_prefix in extensions.items():
        if any(x.startswith(file_prefix) for x in filenames):
            return ext
    return None


def get_tag(classification: Dict[str, str]) -> str:
    sample_type = classification["kind"]

    # Build classification tag
    if "platform" in classification:
        # Add platform information
        sample_type += f":{classification['platform']}"

    if "extension" in classification:
        # Add extension (if not empty)
        extension = classification["extension"]
        if extension:
            sample_type += f":{classification['extension']}"

    # Add misc: if headers doesn't have platform nor extension
    if ":" not in sample_type:
        sample_type = f"misc:{sample_type}"

    return sample_type


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

    def process(self) -> None:
        sample = self.current_task.get_resource("sample")
        sample_class = self._classify(sample)

        file_name = sample.name or "sample"

        if sample_class is None:
            self.log.info(
                "Sample {!r} not recognized (unsupported type)".format(
                    file_name.encode("utf8")
                )
            )
            return

        classification_tag = get_tag(sample_class)
        self.log.info(
            "Classified {!r} as {} and tag {}".format(
                file_name.encode("utf8"), repr(sample_class), classification_tag
            )
        )

        task = self.current_task.derive_task(sample_class)
        # pass the original tags to the next task
        tags = [classification_tag]
        if task.has_payload("tags"):
            tags += task.get_payload("tags")
            task.remove_payload("tags")

        task.add_payload("tags", tags)

        # add a sha256 digest in the outgoing task if there
        # isn't one in the incoming task
        if "sha256" not in task.payload["sample"].metadata:
            task.payload["sample"].metadata["sha256"] = sha256(
                sample.content
            ).hexdigest()

        self.send_task(task)

    def _get_extension(self, name: str) -> str:
        splitted = name.rsplit(".", 1)
        return splitted[-1].lower() if len(splitted) > 1 else ""

    def _classify(self, sample: Resource) -> Optional[Dict[str, str]]:
        sample_type = {
            "type": "sample",
            "stage": "recognized",
            "quality": self.current_task.headers.get("quality", "high"),
        }
        content = sample.content
        magic = self.current_task.get_payload("magic") or pymagic.from_buffer(content)
        extension = self._get_extension(sample.name or "sample")

        # Is PE file?
        if magic.startswith("PE32"):
            sample_type.update(
                {"kind": "runnable", "platform": "win32", "extension": "exe"}
            )
            if magic.startswith("PE32+"):
                sample_type["platform"] = "win64"  # 64-bit only executable
            if "(DLL)" in magic:
                sample_type["extension"] = "dll"
            return sample_type

        # ZIP-contained files?
        def zip_has_file(path: str) -> bool:
            try:
                ZipFile(BytesIO(content)).getinfo(path)
                return True
            except Exception:
                return False

        if magic.startswith("Zip archive data") or magic.startswith(
            "Java archive data (JAR)"
        ):
            if extension == "apk" or zip_has_file("AndroidManifest.xml"):
                sample_type.update(
                    {"kind": "runnable", "platform": "android", "extension": "apk"}
                )
                return sample_type

            if extension == "jar" or zip_has_file("META-INF/MANIFEST.MF"):
                sample_type.update(
                    {
                        "kind": "runnable",
                        "platform": "win32",  # Default platform should be Windows
                        "extension": "jar",
                    }
                )
                return sample_type

        # Dalvik Android files?
        if magic.startswith("Dalvik dex file") or extension == "dex":
            sample_type.update(
                {"kind": "runnable", "platform": "android", "extension": "dex"}
            )
            return sample_type

        # Shockwave Flash?
        if magic.startswith("Macromedia Flash") or extension == "swf":
            sample_type.update(
                {"kind": "runnable", "platform": "win32", "extension": "swf"}
            )
            return sample_type

        # Windows LNK?
        if magic.startswith("MS Windows shortcut") or extension == "lnk":
            sample_type.update(
                {"kind": "runnable", "platform": "win32", "extension": "lnk"}
            )
            return sample_type

        # Is ELF file?
        if magic.startswith("ELF"):
            sample_type.update({"kind": "runnable", "platform": "linux"})
            return sample_type

        # Windows scripts (per extension)
        script_extensions = [
            "vbs",
            "vbe",
            "js",
            "jse",
            "wsh",
            "wsf",
            "hta",
            "cmd",
            "bat",
            "ps1",
        ]
        if extension in script_extensions:
            sample_type.update(
                {"kind": "script", "platform": "win32", "extension": extension}
            )
            return sample_type

        # Office documents
        office_extensions = {
            "doc": "Microsoft Word",
            "xls": "Microsoft Excel",
            "ppt": "Microsoft PowerPoint",
        }
        # Check RTF by libmagic
        if magic.startswith("Rich Text Format"):
            sample_type.update(
                {"kind": "document", "platform": "win32", "extension": "rtf"}
            )
            return sample_type
        # Check Composite Document (doc/xls/ppt) by libmagic and extension
        if magic.startswith("Composite Document File"):
            # MSI installers are also CDFs
            if "MSI Installer" in magic:
                sample_type.update(
                    {"kind": "runnable", "platform": "win32", "extension": "msi"}
                )
                return sample_type
            # If not MSI, treat it like Office document
            sample_type.update(
                {
                    "kind": "document",
                    "platform": "win32",
                }
            )
            if extension[:3] in office_extensions.keys():
                sample_type["extension"] = extension
            else:
                sample_type["extension"] = "doc"
            return sample_type

        # Check docx/xlsx/pptx by libmagic
        for ext, typepart in office_extensions.items():
            if magic.startswith(typepart):
                sample_type.update(
                    {"kind": "document", "platform": "win32", "extension": ext + "x"}
                )
                return sample_type

        # Check RTF by extension
        if extension == "rtf":
            sample_type.update(
                {"kind": "document", "platform": "win32", "extension": "rtf"}
            )
            return sample_type

        # Finally check document type only by extension
        if extension[:3] in office_extensions.keys():
            sample_type.update(
                {"kind": "document", "platform": "win32", "extension": extension}
            )
            return sample_type

        # Unclassified Open XML documents
        if magic.startswith("Microsoft OOXML"):
            try:
                extn = classify_openxml(content)
                if ext:
                    sample_type.update(
                        {
                            "kind": "document",
                            "platform": "win32",
                            "extension": extn,
                        }
                    )
                    return sample_type
            except Exception:
                self.log.exception("Error while trying to classify OOXML")

        # PDF files
        if magic.startswith("PDF document") or extension == "pdf":
            sample_type.update(
                {"kind": "document", "platform": "win32", "extension": "pdf"}
            )
            return sample_type

        # Archives
        archive_assoc = {
            "7z": ["7-zip archive data"],
            "ace": ["ACE archive data"],
            "bz2": ["bzip2 compressed data"],
            "cab": ["Microsoft Cabinet archive data"],
            "gz": ["gzip compressed"],
            "iso": ["ISO 9660 CD-ROM"],
            "lz": ["lzip compressed data"],
            "tar": ["tar archive", "POSIX tar archive"],
            "rar": ["RAR archive data"],
            "udf": ["UDF filesystem data"],
            "xz": ["XZ compressed data"],
            "zip": ["Zip archive data"],
            "zlib": ["zlib compressed data"],
        }
        archive_extensions = [
            "ace",
            "zip",
            "rar",
            "tar",
            "cab",
            "gz",
            "7z",
            "bz2",
            "arj",
            "iso",
            "xz",
            "lz",
            "udf",
            "cab",
            "zlib",
        ]
        for ext in archive_extensions:
            if ext in archive_assoc:
                if any(magic.startswith(x) for x in archive_assoc[ext]):
                    sample_type.update({"kind": "archive", "extension": ext})
                    return sample_type
        if extension in archive_extensions:
            sample_type.update({"kind": "archive", "extension": extension})
            return sample_type

        # E-mail
        email_assoc = {"msg": "Microsoft Outlook Message", "eml": "multipart/mixed"}
        for ext in email_assoc.keys():
            if email_assoc[ext] in magic:
                sample_type.update({"kind": "archive", "extension": ext})
                return sample_type

        if extension in email_assoc.keys():
            sample_type.update({"kind": "archive", "extension": extension})
            return sample_type

        # HTML
        if magic.startswith("HTML document"):
            sample_type.update({"kind": "html"})
            return sample_type

        # Linux scripts
        if ("script" in magic and "executable" in magic) or extension == "sh":
            sample_type.update(
                {"kind": "script", "platform": "linux", "extension": extension}
            )
            return sample_type

        # Content heuristics
        partial = content[:2048] + content[-2048:]

        # Dumped PE file heuristics (PE not recognized by libmagic)
        if b".text" in partial and b"This program cannot be run" in partial:
            sample_type.update(
                {"kind": "dump", "platform": "win32", "extension": "exe"}
            )
            return sample_type

        if len(partial) > 0x40:
            pe_offs = struct.unpack("<H", partial[0x3C:0x3E])[0]
            if partial[pe_offs : pe_offs + 2] == b"PE":
                sample_type.update(
                    {"kind": "dump", "platform": "win32", "extension": "exe"}
                )
                return sample_type

        if partial.startswith(b"MZ"):
            sample_type.update(
                {"kind": "dump", "platform": "win32", "extension": "exe"}
            )
            return sample_type

        # Heuristics for scripts
        try:
            try:
                partial_str = partial.decode(
                    chardet.detect(partial)["encoding"]
                ).lower()
            except Exception:
                self.log.warning("Heuristics disabled - unknown encoding")
            else:
                vbs_keywords = [
                    "end function",
                    "end if",
                    "array(",
                    "sub ",
                    "on error ",
                    "createobject",
                    "execute",
                ]
                js_keywords = [
                    "function ",
                    "function(",
                    "this.",
                    "this[",
                    "new ",
                    "createobject",
                    "activexobject",
                    "var ",
                    "catch",
                ]
                html_keywords = ["<!doctype", "<html", "<script"]
                ps_keywords = [
                    "powershell",
                    "-nop",
                    "bypass",
                    "new-object",
                    "invoke-expression",
                    "frombase64string(",
                    "| iex",
                    "|iex",
                ]
                if (
                    len([True for keyword in html_keywords if keyword in partial_str])
                    >= 2
                ):
                    sample_type.update({"kind": "html"})
                    return sample_type

                if (
                    len([True for keyword in vbs_keywords if keyword in partial_str])
                    >= 2
                ):
                    sample_type.update(
                        {"kind": "script", "platform": "win32", "extension": "vbs"}
                    )
                    return sample_type

                if (
                    len([True for keyword in js_keywords if keyword in partial_str])
                    >= 2
                ):
                    sample_type.update(
                        {"kind": "script", "platform": "win32", "extension": "js"}
                    )
                    return sample_type

                # JSE heuristics
                if re.match("#@~\\^[a-zA-Z0-9+/]{6}==", partial_str):
                    sample_type.update(
                        {
                            "kind": "script",
                            "platform": "win32",
                            "extension": "jse",  # jse is more possible than vbe
                        }
                    )
                    return sample_type
                # Powershell heuristics
                if len(
                    [True for keyword in ps_keywords if keyword.lower() in partial_str]
                ):
                    sample_type.update(
                        {"kind": "script", "platform": "win32", "extension": "ps1"}
                    )
                    return sample_type
                if magic.startswith("ASCII"):
                    sample_type.update(
                        {
                            "kind": "ascii",
                        }
                    )
                    return sample_type
        except Exception as e:
            self.log.exception(e)

        # If not recognized then unsupported
        return None
