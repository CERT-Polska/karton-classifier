import logging
import re
import struct
from io import BytesIO
from typing import Callable
from zipfile import ZipFile, is_zipfile

import chardet  # type: ignore
from pure_magic_rs import MagicDb

from .file_info import FileTypeInfo, get_extension
from .zip_utils import get_zip_filenames

# Karton logger name is the same as Karton identity
logger = logging.getLogger("karton.classifier")

# ---------------------------------------------------------------------------
# Classification lookup tables
# ---------------------------------------------------------------------_re------

# ELF
ELF_ASSOC = {
    "linux": "(GNU/Linux)",
    "freebsd": "(FreeBSD)",
    "netbsd": "(NetBSD)",
    "openbsd": "(SYSV)",
    "solaris": "(Solaris)",
}

# Archives
ZIP_MAGIC = "Zip archive data"
ARCHIVE_ASSOC = {
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
    "zip": [ZIP_MAGIC],
    "zlib": ["zlib compressed data"],
    "lzh": ["  LHa (2.x) archive data", "  LHa 2.x? archive data"],
}
ARCHIVE_EXTENSIONS = {
    "7z",
    "ace",
    "arc",
    "arj",
    "bz2",
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
}

# Java / Android
JAVA_ARCHIVES = [
    ZIP_MAGIC,
    "Java archive data (JAR)",
    "Android package (APK)",
]

# E-mail
EMAIL_ASSOC = {
    "msg": ["Microsoft Outlook Message"],
    "eml": ["multipart/mixed", "RFC 822 mail", "SMTP mail"],
}

# Office documents
OFFICE_EXTENSIONS = {
    "doc": "Microsoft Word",
    "xls": "Microsoft Excel",
    "ppt": "Microsoft PowerPoint",
}

# Various graphics/image file formats
IMAGE_ASSOC = {
    "gif": ["GIF image data"],
    "jpg": ["JPEG image data"],
    "png": ["PNG image data"],
    "webp": ["Web/P image", "WebP image"],
}

# Windows scripts (per extension)
SCRIPT_EXTENSIONS = {
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
}

# Various scripting languages
SCRIPT_ASSOC = {
    "php": ["PHP script"],
    "pl": ["Perl script", "Perl5 module"],
    "py": ["Python script"],
    "rb": ["Ruby script"],
    "scpt": ["AppleScript compiled"],
    "sh": ["Bourne-Again shell", "POSIX shell"],
}

# Content heuristics keywords
VBS_KEYWORDS = [
    "end function",
    "end if",
    "array(",
    "sub ",
    "on error ",
    "createobject",
    "execute",
]
JS_KEYWORDS = [
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
HTML_KEYWORDS = ["<!doctype", "<html", "<script"]
PS_KEYWORDS = [
    "powershell",
    "-nop",
    "bypass",
    "new-object",
    "invoke-expression",
    "frombase64string(",
    "| iex",
    "|iex",
]


def zip_is_xapk(content: bytes) -> bool:
    try:
        names = get_zip_filenames(content)
        if "manifest.json" not in names:
            return False
        return any(n.endswith(".apk") and "/" not in n for n in names)
    except Exception:
        return False


def classify_openxml(content: bytes) -> str | None:
    zipfile = ZipFile(BytesIO(content))
    extensions = {"docx": "word", "pptx": "ppt", "xlsx": "xl"}
    filenames = [x.filename for x in zipfile.filelist]

    for ext, file_prefix in extensions.items():
        if any(x.startswith(file_prefix) for x in filenames):
            return ext
    return None


MagicFromBufferFunction = Callable[[bytes], tuple[str, str]]


def load_magic() -> MagicFromBufferFunction:
    magic_db = MagicDb()

    def wrapper(content: bytes) -> tuple[str, str]:
        try:
            result = magic_db.best_magic_buffer(content)
            magic = result.message if result else "data"
            mime = result.mime_type if result else "application/octet-stream"
        except Exception:
            logger.exception("Got exception from libmagic during file type recognition")
            magic = "data"
            mime = "application/octet-stream"
        return magic, mime

    return wrapper


def recognize_with_magic(
    content: bytes,
    file_name: str,
    magic: str,
    mime: str,
) -> FileTypeInfo:
    extension = get_extension(file_name)
    if magic == "data" and is_zipfile(BytesIO(content)):
        logger.info("libmagic 'data' fallback, classifying as zip.")
        magic = ZIP_MAGIC

    sample_class: FileTypeInfo = {}

    logger.info("Classifying sample with magic: %s, extension: %s", magic, extension)

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
    if any(magic.startswith(x) for x in JAVA_ARCHIVES):
        try:
            zip_filenames = set(get_zip_filenames(content))
        except Exception:
            zip_filenames = set()

        if extension == "apk" or "AndroidManifest.xml" in zip_filenames:
            sample_class.update(
                {"kind": "runnable", "platform": "android", "extension": "apk"}
            )
            return sample_class

        if extension == "jar" or "META-INF/MANIFEST.MF" in zip_filenames:
            sample_class.update(
                {
                    "kind": "runnable",
                    "platform": "win32",  # Default platform should be Windows
                    "extension": "jar",
                }
            )
            return sample_class

        if extension == "xapk" or zip_is_xapk(content):
            sample_class.update(
                {"kind": "runnable", "platform": "android", "extension": "xapk"}
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
    if magic.startswith("ELF"):
        for platform, platform_full in ELF_ASSOC.items():
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
    if magic.startswith(ZIP_MAGIC) and zip_has_mac_app():
        sample_class.update(
            {"kind": "runnable", "platform": "macos", "extension": "app"}
        )
        return sample_class

    for ext, patterns in IMAGE_ASSOC.items():
        if any(pattern in magic for pattern in patterns):
            sample_class.update({"kind": "misc", "extension": ext})
            return sample_class

    if extension in IMAGE_ASSOC.keys():
        sample_class.update({"kind": "misc", "extension": extension})
        return sample_class

    # Is Disk image?
    if magic.startswith("Microsoft Disk Image") or extension == "vhd":
        sample_class.update({"kind": "archive", "extension": "vhd"})
        return sample_class

    if extension in SCRIPT_EXTENSIONS:
        sample_class.update(
            {"kind": "script", "platform": "win32", "extension": extension}
        )
        return sample_class

    # Check RTF by libmagic
    if magic.startswith("Rich Text Format"):
        sample_class.update(
            {"kind": "document", "platform": "win32", "extension": "rtf"}
        )
        return sample_class
    # Check OLE 2 Compound Document by magic and extension
    if magic.startswith("OLE 2 Compound Document"):
        # MSI installers are also CDFs
        if "Microsoft Windows Installer" in magic:
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

        for ext, typepart in OFFICE_EXTENSIONS.items():
            if f": {typepart}" in magic:
                sample_class["extension"] = ext
                return sample_class

        if extension[:3] in OFFICE_EXTENSIONS.keys():
            sample_class["extension"] = extension
        else:
            sample_class["extension"] = "doc"
        return sample_class

    # Check docx/xlsx/pptx by libmagic
    for ext, typepart in OFFICE_EXTENSIONS.items():
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
    if extension[:3] in OFFICE_EXTENSIONS.keys():
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
            logger.exception("Error while trying to classify OOXML")

    # Check Password-Encrypted Open XML documents
    if magic == "CDFV2 Encrypted" and mime == "application/encrypted":
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
    if magic == "JSON data" or mime == "application/json":
        sample_class.update({"kind": "json"})
        return sample_class

    def apply_archive_headers(extension: str) -> FileTypeInfo:
        headers: FileTypeInfo = {"kind": "archive", "extension": extension}
        if extension == "cpio":
            # Fix-up for pure-magic
            # Remove after it recognizes binary CPIO header
            headers["mime"] = "application/x-cpio"
        return headers

    # Special case of UDF: 'ISO 9660 CD-ROM ... + UDF filesystem data'
    if magic.startswith("ISO 9660 CD-ROM") and "+ UDF filesystem data" in magic:
        return apply_archive_headers("udf")

    for archive_extension, assocs in ARCHIVE_ASSOC.items():
        if any(magic.startswith(assoc) for assoc in assocs):
            return apply_archive_headers(archive_extension)

    if extension in ARCHIVE_EXTENSIONS:
        return apply_archive_headers(extension)

    for ext, patterns in EMAIL_ASSOC.items():
        if any(pattern in magic for pattern in patterns):
            sample_class.update({"kind": "archive", "extension": ext})
            return sample_class

    if extension in EMAIL_ASSOC.keys():
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

    # Wallets
    if content.startswith(b"\xbaWALLET"):
        sample_class.update(
            {
                "kind": "armory-wallet",
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

    for ext, patterns in SCRIPT_ASSOC.items():
        if any(pattern in magic for pattern in patterns):
            sample_class.update({"kind": "script", "extension": ext})
            return sample_class

    if extension in SCRIPT_ASSOC.keys():
        sample_class.update({"kind": "script", "extension": extension})
        return sample_class

    # Content heuristics
    if len(content) >= 4096:
        # take only the first and last 2048 bytes from the content
        partial = content[:2048] + content[-2048:]
    else:
        # take the whole content
        partial = content

    if partial.startswith((b"\xc7\x71", b"\x71\xc7")) and b"TRAILER!!!" in partial:
        return apply_archive_headers("cpio")

    # Dumped PE file heuristics (PE not recognized by libmagic)
    if b".text" in partial and b"This program cannot be run" in partial:
        sample_class.update({"kind": "dump", "platform": "win32", "extension": "exe"})
        return sample_class

    if len(partial) > 0x40:
        pe_offs = struct.unpack("<H", partial[0x3C:0x3E])[0]
        if partial[pe_offs : pe_offs + 2] == b"PE":
            sample_class.update(
                {"kind": "dump", "platform": "win32", "extension": "exe"}
            )
            return sample_class

    if partial.startswith(b"MZ"):
        sample_class.update({"kind": "dump", "platform": "win32", "extension": "exe"})
        return sample_class

    # Telegram
    if partial.startswith(b"TDF$"):
        sample_class.update(
            {
                "kind": "telegram-desktop-file",
            }
        )
        return sample_class

    if partial.startswith(b"TDEF"):
        sample_class.update(
            {
                "kind": "telegram-desktop-encrypted-file",
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
    # XML 1.0 document, ASCII text, with very long lines (581), with
    # CRLF line terminators
    # Non-ISO extended-ASCII text, with no line terminators
    # troff or preprocessor input, ASCII text, with CRLF line terminators
    if "ASCII text" in magic:
        sample_class.update(
            {
                "kind": "ascii",
            }
        )

    if magic.startswith("CSV "):
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
    if "UTF-8 text" in magic:
        sample_class.update(
            {
                "kind": "utf-8",
            }
        )

    # Heuristics for scripts
    try:
        partial_str = partial.decode(chardet.detect(partial)["encoding"]).lower()
    except Exception:
        logger.warning("Heuristics disabled - unknown encoding")
        partial_str = None

    if partial_str:
        if len([True for keyword in HTML_KEYWORDS if keyword in partial_str]) >= 2:
            sample_class.update({"kind": "html"})
            return sample_class

        if len([True for keyword in VBS_KEYWORDS if keyword in partial_str]) >= 2:
            sample_class.update(
                {"kind": "script", "platform": "win32", "extension": "vbs"}
            )
            return sample_class
        # Powershell heuristics
        if len([True for keyword in PS_KEYWORDS if keyword.lower() in partial_str]):
            sample_class.update(
                {"kind": "script", "platform": "win32", "extension": "ps1"}
            )
            return sample_class
        # JS heuristics
        if len([True for keyword in JS_KEYWORDS if keyword in partial_str]) >= 2:
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
