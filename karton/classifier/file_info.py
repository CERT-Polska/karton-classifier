from typing import NotRequired, TypedDict


class FileTypeInfo(TypedDict):
    kind: NotRequired[str]
    platform: NotRequired[str]
    extension: NotRequired[str]
    # MIME type override
    mime: NotRequired[str]
    # for Yara rules
    rule_name: NotRequired[str]


def get_extension(name: str) -> str:
    splitted = name.rsplit(".", 1)
    return splitted[-1].lower() if len(splitted) > 1 else ""


def file_type_info_to_tag(file_type_info: FileTypeInfo) -> str:
    sample_type = file_type_info["kind"]

    # Build classification tag
    if file_type_info.get("platform") is not None:
        # Add platform information
        sample_type += f":{file_type_info['platform']}"

    if file_type_info.get("extension") is not None:
        # Add extension (if not empty)
        extension = file_type_info["extension"]
        if extension:
            sample_type += f":{file_type_info['extension']}"

    # Add misc: when header doesn't have platform nor extension
    if ":" not in sample_type:
        sample_type = f"misc:{sample_type}"

    return sample_type
