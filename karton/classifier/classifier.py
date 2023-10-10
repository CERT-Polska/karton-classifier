import argparse
import re
import struct
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import Callable, Dict, List, Optional, cast
from zipfile import ZipFile

import chardet  # type: ignore
import magic as pymagic  # type: ignore
import yara  # type: ignore
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


def load_yara_rules(path: Path) -> yara.Rules:
    rule_files = {}
    for f in path.glob("*.yar"):
        rule_files[f.name] = f.as_posix()

    rules = yara.compile(filepaths=rule_files)
    for r in rules:
        if not r.meta.get("kind"):
            raise RuntimeError(
                f"Rule {r.identifier} does not have a `kind` meta attribute"
            )

    return rules


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

    # Add misc: when header doesn't have platform nor extension
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

        yara_directory = self.config.get("classifier", "yara_rules", fallback=None)
        if yara_directory:
            yara_p = Path(yara_directory)
            if not yara_p.is_dir():
                raise NotADirectoryError(yara_p)

            self.yara_rules = load_yara_rules(yara_p)
            self.log.info("Loaded %d yara classifier rules", len(list(self.yara_rules)))
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

    def _magic_from_content(self) -> Callable:
        get_magic = pymagic.Magic(mime=False)
        get_mime = pymagic.Magic(mime=True)

        def wrapper(content, mime):
            if mime:
                return get_mime.from_buffer(content)
            else:
                return get_magic.from_buffer(content)

        return wrapper

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")

        sample_classes = []

        if self.yara_rules:
            sample_classes += self._classify_yara(task)

        filemagic_classification = self._classify_filemagic(task)
        if filemagic_classification["kind"] is not None:
            sample_classes.append(filemagic_classification)

        file_name = sample.name or "sample"

        if not sample_classes:
            self.log.info(
                "Sample {} (sha256: {}) not recognized (unsupported type)".format(
                    file_name, sample.sha256)
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

        for sample_class in sample_classes:

            classification_tag = get_tag(sample_class)
            self.log.info(
                "Classified %r as %r and tag %s",
                file_name.encode("utf8"),
                sample_class,
                classification_tag,
            )

            derived_headers = {
                "type": "sample",
                "stage": "recognized",
                "kind": sample_class["kind"],
                "quality": task.headers.get("quality", "high"),
            }
            if sample_class.get("platform") is not None:
                derived_headers["platform"] = sample_class["platform"]
            if sample_class.get("extension") is not None:
                derived_headers["extension"] = sample_class["extension"]
            if sample_class.get("mime") is not None:
                derived_headers["mime"] = sample_class["mime"]
            if sample_class.get("rule-name") is not None:
                derived_headers["rule-name"] = sample_class["rule-name"]

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

    def _classify_filemagic(self, task: Task) -> Dict[str, Optional[str]]:
        sample = task.get_resource("sample")
        content = cast(bytes, sample.content)
        file_name = sample.name
        if len(sample.content) == 0:
            self.log.info(
                "Sample: {!r} has no content".format(file_name.encode("utf8"))
            )

        file_name = sample.name
        if len(sample.content) == 0:
            self.log.info("Sample: {} has no content".format(file_name))

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

        self.log.info(
            "Classifying sample with magic: %s, extension: %s", magic, extension
        )

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

        # Is COM file?
        if magic.startswith("COM executable for DOS"):
            sample_class.update(
                {"kind": "runnable", "platform": "win32", "extension": "com"}
            )
            return sample_class

        # Is PC MBR?
        if magic.startswith("DOS/MBR boot sector"):
            sample_class.update({"kind": "runnable", "extension": "mbr"})
            return sample_class

        # ZIP-contained files?
        def zip_has_file(path: str) -> bool:
            try:
                ZipFile(BytesIO(content)).getinfo(path)
                return True
            except Exception:
                return False

        JAVA_ARCHIVES = [
            "Zip archive data",
            "Java archive data (JAR)",
            "Android package (APK)",
        ]

        if any(magic.startswith(x) for x in JAVA_ARCHIVES):
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

        # Windows CHM?
        if magic.startswith("MS Windows HtmlHelp Data") or extension == "chm":
            sample_class.update(
                {"kind": "runnable", "platform": "win32", "extension": "chm"}
            )
            return sample_class

        # Is ELF file?
        elf_assoc = {
            "linux": "(GNU/Linux)",
            "freebsd": "(FreeBSD)",
            "netbsd": "(NetBSD)",
            "openbsd": "(SYSV)",
            "solaris": "(Solaris)",
        }
        if magic.startswith("ELF"):
            for platform, platform_full in elf_assoc.items():
                if platform_full in magic:
                    sample_class.update(
                        {"kind": "runnable", "platform": platform, "extension": "elf"}
                    )
                    return sample_class

            sample_class.update({"kind": "runnable", "extension": "elf"})
            return sample_class

        # Is XCOFF64 file (for AIX)?
        if magic.startswith("64-bit XCOFF"):
            sample_class.update(
                {"kind": "runnable", "platform": "aix", "extension": "xcoff"}
            )
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

        # Is Mach-O file?
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

        # Various graphics/image file formats
        image_assoc = {
            "gif": ["GIF image data"],
            "jpg": ["JPEG image data"],
            "png": ["PNG image data"],
        }

        for ext, patterns in image_assoc.items():
            if any(pattern in magic for pattern in patterns):
                sample_class.update({"kind": "misc", "extension": ext})
                return sample_class

        if extension in image_assoc.keys():
            sample_class.update({"kind": "misc", "extension": extension})
            return sample_class

        # Is Disk image?
        if magic.startswith("Microsoft Disk Image") or extension == "vhd":
            sample_class.update({"kind": "archive", "extension": "vhd"})
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

        # Check Password-Encrypted Open XML documents
        if magic == "CDFV2 Encrypted" and magic_mime == "application/encrypted":
            # if extension is known before this step, the document would have
            # been already classified - if we are here, no extension is known
            sample_class.update({"kind": "document", "platform": "win32"})
            return sample_class

        # PDF files
        if magic.startswith("PDF document") or extension == "pdf":
            sample_class.update(
                {"kind": "document", "platform": "win32", "extension": "pdf"}
            )
            return sample_class

        # JSON files
        if magic == "JSON data" or magic_mime == "application/json":
            sample_class.update({"kind": "json"})
            return sample_class

        # Ransomware encrypted files, check this before archive detection
        # as some of them would be detected for example as zip archives
        if content.startswith(b"PK"):
            if file_name.endswith(".zatp"):
                sample_class.update({"kind": "zatp_ransomware_encryped"})
                return sample_class
            if file_name.endswith(".ygvb"):
                sample_class.update({"kind": "ygvb_ransomware_encryped"})
                return sample_class
            if file_name.endswith(".uyro"):
                sample_class.update({"kind": "uyro_ransomware_encryped"})
                return sample_class

        if content.startswith(b"20 et"):
            if file_name.endswith(".mbtf"):
                sample_class.update({"kind": "mbtf_ransomware_encryped"})
                return sample_class

        # Archives
        archive_assoc = {
            "7z": ["7-zip archive data"],
            "ace": ["ACE archive data"],
            "bz2": ["bzip2 compressed data"],
            "cab": ["Microsoft Cabinet archive data"],
            "cpio": ["cpio archive"],
            "gz": ["gzip compressed"],
            "iso": ["ISO 9660 CD-ROM"],
            "lz": ["lzip compressed data"],
            "tar": ["tar archive", "POSIX tar archive"],
            "rar": ["RAR archive data"],
            "udf": ["UDF filesystem data"],
            "xz": ["XZ compressed data"],
            "zip": ["Zip archive data"],
            "zlib": ["zlib compressed data"],
            "lzh": ["  LHa (2.x) archive data", "  LHa 2.x? archive data"],
        }
        archive_extensions = [
            "7z",
            "ace",
            "arc",
            "arj",
            "bz2",
            "cab",
            "cab",
            "cpio",
            "gz",
            "iso",
            "lz",
            "lzh",
            "rar",
            "tar",
            "udf",
            "xz",
            "zip",
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

        # PGP
        if magic.startswith("PGP") or magic.startswith("OpenPGP"):
            sample_class.update(
                {
                    "kind": "pgp",
                }
            )
            return sample_class

        # PCAP
        if magic.startswith(("pcap capture file", "tcpdump capture file")):
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

        # Images
        if magic.startswith("JPEG"):
            sample_class.update(
                {
                    "kind": "jpeg",
                }
            )
            return sample_class

        if magic.startswith("PNG"):
            sample_class.update(
                {
                    "kind": "png",
                }
            )
            return sample_class

        # Wallets
        if content.startswith(b"\xbaWALLET"):
            sample_class.update(
                {
                    "kind": "armory_wallet",
                }
            )
            return sample_class

        # IOT / OT
        if content.startswith(b"SECO"):
            sample_class.update(
                {
                    "kind": "seco",
                }
            )
            return sample_class

        # HTML
        if magic.startswith("HTML document"):
            sample_class.update({"kind": "html"})
            return sample_class

        # Various scripting languages
        script_assoc = {
            "php": ["PHP script"],
            "pl": ["Perl script", "Perl5 module"],
            "py": ["Python script"],
            "rb": ["Ruby script"],
            "scpt": ["AppleScript compiled"],
            "sh": ["Bourne-Again shell", "POSIX shell"],
        }
        for ext, patterns in script_assoc.items():
            if any(pattern in magic for pattern in patterns):
                sample_class.update({"kind": "script", "extension": ext})
                return sample_class

        if extension in script_assoc.keys():
            sample_class.update({"kind": "script", "extension": ext})
            return sample_class

        # Content heuristics
        if len(content) >= 4096:
            # take only the first and last 2048 bytes from the content
            partial = content[:2048] + content[-2048:]
        else:
            # take the whole content
            partial = content

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

        # Telegram
        if partial.startswith(b"TDF$"):
            sample_class.update(
                {
                    "kind": "telegram_desktop_file",
                }
            )
            return sample_class

        if partial.startswith(b"TDEF"):
            sample_class.update(
                {
                    "kind": "telegram_desktop_encrypted_file",
                }
            )
            return sample_class

        #
        # Detection of text-files: As these files also could be scripts, do not
        # immediately return sample_class after a successful detection. Like this
        # heuristics part further below can override detection
        #

        # magic samples of ASCII files:
        # XML 1.0 document, ASCII text
        # XML 1.0 document, ASCII text, with very long lines (581), with CRLF line terminators
        # Non-ISO extended-ASCII text, with no line terminators
        # troff or preprocessor input, ASCII text, with CRLF line terminators
        if "ASCII" in magic:
            sample_class.update(
                {
                    "kind": "ascii",
                }
            )

        if magic.startswith("CSV text"):
            sample_class.update(
                {
                    "kind": "csv",
                }
            )

        if magic.startswith("ISO-8859"):
            sample_class.update(
                {
                    "kind": "iso-8859-1",
                }
            )

        # magic samples of UTF-8 files:
        # Unicode text, UTF-8 text, with CRLF line terminators
        # XML 1.0 document, Unicode text, UTF-8 text
        if "UTF-8" in magic:
            sample_class.update(
                {
                    "kind": "utf-8",
                }
            )

        #if sample_class['kind'] is None:
        #    # as libmagic sometimes fails to detect encoding of text files
        #    chardet_prediction = chardet.detect(partial)['encoding']
        #    self.log.info(f'chardet classification: {chardet_prediction} magic: {magic}')
        #    if chardet_prediction is not None:
        #        sample_class.update(
        #            {
        #                "kind": chardet_prediction
        #            }
        #        )

        # Heuristics for scripts
        try:
            partial_str = partial.decode(chardet.detect(partial)["encoding"]).lower()
        except Exception:
            self.log.warning("Heuristics disabled - unknown encoding")
            # Detect steam files based on the file name
            if re.match(r"ssfn\d{16,19}", file_name):
                sample_class.update(
                    {
                        "kind": "steam",
                    }
                )
            return sample_class

        if partial_str:
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
            if len([True for keyword in html_keywords if keyword in partial_str]) >= 2:
                sample_class.update({"kind": "html"})
                return sample_class

            if len([True for keyword in vbs_keywords if keyword in partial_str]) >= 2:
                sample_class.update(
                    {"kind": "script", "platform": "win32", "extension": "vbs"}
                )
                return sample_class
            # Powershell heuristics
            if len([True for keyword in ps_keywords if keyword.lower() in partial_str]):
                sample_class.update(
                    {"kind": "script", "platform": "win32", "extension": "ps1"}
                )
                return sample_class
            # JS heuristics
            if len([True for keyword in js_keywords if keyword in partial_str]) >= 2:
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

        # If not recognized then unsupported
        return sample_class

    def _classify_yara(self, task: Task) -> List[Dict[str, Optional[str]]]:
        sample = task.get_resource("sample")
        content = cast(bytes, sample.content)

        sample_classes = []

        yara_matches = self.yara_rules.match(data=content)
        for match in yara_matches:
            sample_class = {}
            sample_class["rule-name"] = match.rule
            sample_class["kind"] = match.meta["kind"]
            if match.meta.get("platform"):
                sample_class["platform"] = match.meta["platform"]
            if match.meta.get("extension"):
                sample_class["extension"] = match.meta["extension"]

            self.log.info("Matched the sample using Yara rule %s", match.rule)
            sample_classes.append(sample_class)

        return sample_classes
