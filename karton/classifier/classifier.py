import re
import struct
from hashlib import sha256
from io import BytesIO
from typing import Callable, Dict, Optional, cast
from zipfile import ZipFile

import chardet  # type: ignore
import magic as pymagic  # type: ignore
from karton.core import Config, Karton, Task
from karton.core.backend import KartonBackend

from .__version__ import __version__


def classify_openxml(content: bytes) -> Optional[str]:
    zipfile = ZipFile(BytesIO(content))
    extensions = {"docx": "word", "pptx": "ppt", "xlsx": "xl"}
    filenames = [x.filename for x in zipfile.filelist]

    for ext, file_prefix in extensions.items():
        if any(x.startswith(file_prefix) for x in filenames):
            return ext
    return None


def get_tag(classification: Dict) -> str:
    sample_type = classification["kind"]

    # Build classification tag
    if classification.get("platform") is not None:
        # Add platform information
        sample_type += f":{classification['platform']}"

    if classification.get("extension") is not None:
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

    def __init__(
        self,
        config: Config = None,
        identity: str = None,
        backend: KartonBackend = None,
        magic: Callable = None,
    ) -> None:
        super().__init__(config=config, identity=identity, backend=backend)
        self._magic = magic or self._magic_from_content()

    def _magic_from_content(self) -> Callable:
        get_magic = pymagic.Magic(mime=False)
        get_mime = pymagic.Magic(mime=True)

        def wrapper(content, mime):
            if mime:
                return get_mime.from_buffer(content)
            else:
                return get_magic.from_buffer(content)

        return wrapper

    def process(self, task: Task) -> None:  # type: ignore
        sample = task.get_resource("sample")
        sample_class = self._classify(task)

        file_name = sample.name or "sample"

        if sample_class is None:
            self.log.info(
                "Sample {!r} not recognized (unsupported type)".format(
                    file_name.encode("utf8")
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

        classification_tag = get_tag(sample_class)
        self.log.info(
            "Classified {!r} as {} and tag {}".format(
                file_name.encode("utf8"), repr(sample_class), classification_tag
            )
        )

        derived_headers = {
            "type": "sample",
            "stage": "recognized",
            "quality": task.headers.get("quality", "high"),
            "mime": sample_class["mime"],
        }
        if sample_class.get("kind") is not None:
            derived_headers["kind"] = sample_class["kind"]
        if sample_class.get("platform") is not None:
            derived_headers["platform"] = sample_class["platform"]
        if sample_class.get("extension") is not None:
            derived_headers["extension"] = sample_class["extension"]

        derived_task = task.derive_task(derived_headers)

        # pass the original tags to the next task
        tags = [classification_tag]
        if derived_task.has_payload("tags"):
            tags += derived_task.get_payload("tags")
            derived_task.remove_payload("tags")

        derived_task.add_payload("tags", tags)

        # if present the magic description is added as a playload
        if "magic" in sample_class:
            derived_task.add_payload("magic", sample_class["magic"])

        # add a sha256 digest in the outgoing task if there
        # isn't one in the incoming task
        if "sha256" not in derived_task.payload["sample"].metadata:
            derived_task.payload["sample"].metadata["sha256"] = sha256(
                cast(bytes, sample.content)
            ).hexdigest()

        self.send_task(derived_task)

    def _get_extension(self, name: str) -> str:
        splitted = name.rsplit(".", 1)
        return splitted[-1].lower() if len(splitted) > 1 else ""

    def _classify(self, task: Task) -> Optional[Dict[str, Optional[str]]]:
        sample = task.get_resource("sample")
        content = cast(bytes, sample.content)

        magic = task.get_payload("magic") or ""
        magic_mime = task.get_payload("mime") or ""
        try:
            magic = self._magic(content, mime=False)
            magic_mime = self._magic(content, mime=True)
        except Exception as ex:
            self.log.warning(f"unable to get magic: {ex}")

        extension = self._get_extension(sample.name or "sample")
        sample_class = {
            "magic": magic if magic else None,
            "mime": magic_mime if magic_mime else None,
            "kind": None,
            "platform": None,
            "extension": None,
        }

        # Is PE file?
        if magic.startswith("PE32") or magic.startswith("MS-DOS executable PE32"):
            sample_class.update(
                {"kind": "runnable", "platform": "win32", "extension": "exe"}
            )
            if magic.startswith("PE32+"):
                sample_class["platform"] = "win64"  # 64-bit only executable
            if "(DLL)" in magic:
                sample_class["extension"] = "dll"
            return sample_class

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
                sample_class.update(
                    {"kind": "runnable", "platform": "android", "extension": "apk"}
                )
                return sample_class

            if extension == "jar" or zip_has_file("META-INF/MANIFEST.MF"):
                sample_class.update(
                    {
                        "kind": "runnable",
                        "platform": "win32",  # Default platform should be Windows
                        "extension": "jar",
                    }
                )
                return sample_class

        # Dalvik Android files?
        if magic.startswith("Dalvik dex file") or extension == "dex":
            sample_class.update(
                {"kind": "runnable", "platform": "android", "extension": "dex"}
            )
            return sample_class

        # Shockwave Flash?
        if magic.startswith("Macromedia Flash") or extension == "swf":
            sample_class.update(
                {"kind": "runnable", "platform": "win32", "extension": "swf"}
            )
            return sample_class

        # Windows LNK?
        if magic.startswith("MS Windows shortcut") or extension == "lnk":
            sample_class.update(
                {"kind": "runnable", "platform": "win32", "extension": "lnk"}
            )
            return sample_class

        # Is ELF file?
        if magic.startswith("ELF"):
            sample_class.update({"kind": "runnable", "platform": "linux"})
            return sample_class

        # Is PKG file?
        if magic.startswith("xar archive") or extension == "pkg":
            sample_class.update(
                {"kind": "runnable", "platform": "macos", "extension": "pkg"}
            )
            return sample_class

        # Is DMG file?
        if extension == "dmg" or all(
            [
                len(content) > 512,
                content[-512:][:4] == b"koly",
                content[-512:][8:12] == b"\x00\x00\x02\x00",
            ]
        ):
            sample_class.update(
                {"kind": "runnable", "platform": "macos", "extension": "dmg"}
            )
            return sample_class

        # Is mach-o file?
        if magic.startswith("Mach-O"):
            sample_class.update({"kind": "runnable", "platform": "macos"})
            return sample_class

        def zip_has_mac_app() -> bool:
            try:
                zipfile = ZipFile(BytesIO(content))
                return any(
                    x.filename.lower().endswith(".app/contents/info.plist")
                    for x in zipfile.filelist
                )
            except Exception:
                return False

        # macos app within zip
        if magic.startswith("Zip archive data") and zip_has_mac_app():
            sample_class.update(
                {"kind": "runnable", "platform": "macos", "extension": "app"}
            )
            return sample_class

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
            sample_class.update(
                {"kind": "script", "platform": "win32", "extension": extension}
            )
            return sample_class

        # Office documents
        office_extensions = {
            "doc": "Microsoft Word",
            "xls": "Microsoft Excel",
            "ppt": "Microsoft PowerPoint",
        }
        # Check RTF by libmagic
        if magic.startswith("Rich Text Format"):
            sample_class.update(
                {"kind": "document", "platform": "win32", "extension": "rtf"}
            )
            return sample_class
        # Check Composite Document (doc/xls/ppt) by libmagic and extension
        if magic.startswith("Composite Document File"):
            # MSI installers are also CDFs
            if "MSI Installer" in magic:
                sample_class.update(
                    {"kind": "runnable", "platform": "win32", "extension": "msi"}
                )
                return sample_class
            # If not MSI, treat it like Office document
            sample_class.update(
                {
                    "kind": "document",
                    "platform": "win32",
                }
            )

            for ext, typepart in office_extensions.items():
                if f"Name of Creating Application: {typepart}" in magic:
                    sample_class["extension"] = ext
                    return sample_class

            if extension[:3] in office_extensions.keys():
                sample_class["extension"] = extension
            else:
                sample_class["extension"] = "doc"
            return sample_class

        # Check docx/xlsx/pptx by libmagic
        for ext, typepart in office_extensions.items():
            if magic.startswith(typepart):
                sample_class.update(
                    {"kind": "document", "platform": "win32", "extension": ext + "x"}
                )
                return sample_class

        # Check RTF by extension
        if extension == "rtf":
            sample_class.update(
                {"kind": "document", "platform": "win32", "extension": "rtf"}
            )
            return sample_class

        # Finally check document type only by extension
        if extension[:3] in office_extensions.keys():
            sample_class.update(
                {"kind": "document", "platform": "win32", "extension": extension}
            )
            return sample_class

        # Unclassified Open XML documents
        if magic.startswith("Microsoft OOXML"):
            try:
                extn = classify_openxml(content)
                if extn:
                    sample_class.update(
                        {
                            "kind": "document",
                            "platform": "win32",
                            "extension": extn,
                        }
                    )
                    return sample_class
            except Exception:
                self.log.exception("Error while trying to classify OOXML")

        # PDF files
        if magic.startswith("PDF document") or extension == "pdf":
            sample_class.update(
                {"kind": "document", "platform": "win32", "extension": "pdf"}
            )
            return sample_class

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

        def apply_archive_headers(extension):
            headers = {"kind": "archive", "extension": extension}
            if extension == "xz":
                # libmagic >= 5.40 generates correct MIME type for XZ archives
                headers["mime"] = "application/x-xz"
            sample_class.update(headers)
            return sample_class

        for archive_extension, assocs in archive_assoc.items():
            if any(magic.startswith(assoc) for assoc in assocs):
                return apply_archive_headers(archive_extension)

        if extension in archive_extensions:
            return apply_archive_headers(extension)

        # E-mail
        email_assoc = {
            "msg": ["Microsoft Outlook Message"],
            "eml": ["multipart/mixed", "RFC 822 mail", "SMTP mail"],
        }
        for ext, patterns in email_assoc.items():
            if any(pattern in magic for pattern in patterns):
                sample_class.update({"kind": "archive", "extension": ext})
                return sample_class

        if extension in email_assoc.keys():
            sample_class.update({"kind": "archive", "extension": extension})
            return sample_class

        # HTML
        if magic.startswith("HTML document"):
            sample_class.update({"kind": "html"})
            return sample_class

        # Linux scripts
        if ("script" in magic and "executable" in magic) or extension == "sh":
            sample_class.update(
                {"kind": "script", "platform": "linux", "extension": extension}
            )
            return sample_class

        # Content heuristics
        partial = content[:2048] + content[-2048:]

        # Dumped PE file heuristics (PE not recognized by libmagic)
        if b".text" in partial and b"This program cannot be run" in partial:
            sample_class.update(
                {"kind": "dump", "platform": "win32", "extension": "exe"}
            )
            return sample_class

        if len(partial) > 0x40:
            pe_offs = struct.unpack("<H", partial[0x3C:0x3E])[0]
            if partial[pe_offs : pe_offs + 2] == b"PE":
                sample_class.update(
                    {"kind": "dump", "platform": "win32", "extension": "exe"}
                )
                return sample_class

        if partial.startswith(b"MZ"):
            sample_class.update(
                {"kind": "dump", "platform": "win32", "extension": "exe"}
            )
            return sample_class

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
                    sample_class.update({"kind": "html"})
                    return sample_class

                if (
                    len([True for keyword in vbs_keywords if keyword in partial_str])
                    >= 2
                ):
                    sample_class.update(
                        {"kind": "script", "platform": "win32", "extension": "vbs"}
                    )
                    return sample_class
                # Powershell heuristics
                if len(
                    [True for keyword in ps_keywords if keyword.lower() in partial_str]
                ):
                    sample_class.update(
                        {"kind": "script", "platform": "win32", "extension": "ps1"}
                    )
                    return sample_class
                # JS heuristics
                if (
                    len([True for keyword in js_keywords if keyword in partial_str])
                    >= 2
                ):
                    sample_class.update(
                        {"kind": "script", "platform": "win32", "extension": "js"}
                    )
                    return sample_class
                # JSE heuristics
                if re.match("#@~\\^[a-zA-Z0-9+/]{6}==", partial_str):
                    sample_class.update(
                        {
                            "kind": "script",
                            "platform": "win32",
                            "extension": "jse",  # jse is more possible than vbe
                        }
                    )
                    return sample_class
                if magic.startswith("ASCII"):
                    sample_class.update(
                        {
                            "kind": "ascii",
                        }
                    )
                    return sample_class
                if magic.startswith("ISO-8859"):
                    sample_class.update(
                        {
                            "kind": "iso-8859-1",
                        }
                    )
                    return sample_class
                if magic.startswith("UTF-8"):
                    sample_class.update(
                        {
                            "kind": "utf-8",
                        }
                    )
                    return sample_class
                if magic.startswith("PGP"):
                    sample_class.update(
                        {
                            "kind": "pgp",
                        }
                    )
                    return sample_class
                if magic.startswith("pcap capture file"):
                    sample_class.update(
                        {
                            "kind": "pcap",
                        }
                    )
                    return sample_class
                if magic.startswith("pcap") and "ng capture file" in magic:
                    sample_class.update(
                        {
                            "kind": "pcapng",
                        }
                    )
                    return sample_class
        except Exception as e:
            self.log.exception(e)

        # If not recognized then unsupported
        return None
