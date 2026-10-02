import struct
from io import BytesIO
from zipfile import BadZipFile, ZipFile


def recover_zip_filenames(content: bytes) -> list[str]:
    search_start = max(0, len(content) - 0xFFFF - 22)
    end_record_offset = content.rfind(b"PK\x05\x06", search_start)
    if end_record_offset < 0:
        raise BadZipFile("End of central directory not found")

    try:
        end_record = struct.unpack_from("<4s4H2LH", content, end_record_offset)
    except struct.error:
        raise BadZipFile("Truncated end of central directory") from None

    (
        _,
        disk_number,
        central_directory_disk,
        entries_on_disk,
        entries_total,
        central_directory_size,
        central_directory_offset,
        comment_size,
    ) = end_record
    if end_record_offset + 22 + comment_size != len(content):
        raise BadZipFile("Bad end of central directory")
    if (
        disk_number != 0
        or central_directory_disk != 0
        or entries_on_disk != entries_total
    ):
        raise BadZipFile("Multi-disk ZIP files are not supported")
    if (
        entries_total == 0xFFFF
        or central_directory_size == 0xFFFFFFFF
        or central_directory_offset == 0xFFFFFFFF
    ):
        raise BadZipFile("ZIP64 central directory is not supported")

    concatenated_offset = (
        end_record_offset - central_directory_size - central_directory_offset
    )
    central_directory_start = central_directory_offset + concatenated_offset
    central_directory_end = central_directory_start + central_directory_size
    if (
        concatenated_offset < 0
        or central_directory_start < 0
        or central_directory_end != end_record_offset
    ):
        raise BadZipFile("Bad offset for central directory")

    filenames = []
    offset = central_directory_start
    for _ in range(entries_total):
        try:
            header = struct.unpack_from("<4s6H3L5H2L", content, offset)
        except struct.error:
            raise BadZipFile("Truncated central directory") from None
        if header[0] != b"PK\x01\x02":
            raise BadZipFile("Bad magic number for central directory")

        flags = header[3]
        filename_size, extra_size, comment_size = header[10:13]
        filename_start = offset + 46
        filename_end = filename_start + filename_size
        record_end = filename_end + extra_size + comment_size
        if record_end > central_directory_end:
            raise BadZipFile("Truncated central directory entry")

        encoding = "utf-8" if flags & 0x800 else "cp437"
        try:
            filename = content[filename_start:filename_end].decode(encoding)
        except UnicodeDecodeError:
            raise BadZipFile("Bad filename in central directory") from None
        filenames.append(filename.split("\0", 1)[0])
        offset = record_end

    if offset != central_directory_end:
        raise BadZipFile("Bad central directory size")
    return filenames


def get_zip_filenames(content: bytes) -> list[str]:
    try:
        with ZipFile(BytesIO(content)) as zipfile:
            return zipfile.namelist()
    except BadZipFile as exc:
        message = str(exc)
        if not message.startswith("Corrupt extra field ") or message.startswith(
            "Corrupt extra field 0001 "
        ):
            raise
        return recover_zip_filenames(content)
