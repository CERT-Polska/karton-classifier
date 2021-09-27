import ctypes.util
import os
import pathlib
import re

import pytest

# If you want to test pymagic using specific libmagic version:
# - put `libmagic.so` and `magic.mgc` in `tests/libmagic` directory
# - call LIBMAGIC_PRELOAD=FILE5_38 pytest if 5.38 is expected libmagic version:

tests_dir = pathlib.Path(__file__).parent
expected_libmagic = os.environ.get("LIBMAGIC_PRELOAD")

if expected_libmagic:
    version_match = re.match(r"FILE(\d)_(\d\d)", expected_libmagic)
    if not version_match:
        raise RuntimeError("LIBMAGIC_PRELOAD value doesn't match FILEx_xx format")
    expected_version = int("".join(version_match.groups()))

    libmagic_file = tests_dir / "libmagic" / "libmagic.so"
    database_file = tests_dir / "libmagic" / "magic.mgc"
    if not libmagic_file.exists() or not database_file.exists():
        raise RuntimeError("LIBMAGIC_PRELOAD is set, but libmagic binaries are missing")

    # libmagic is loaded during python-magic import.
    # We need to monkeypatch find_library to enforce
    # loading 'magic' from specified path
    ctypes_find_library = ctypes.util.find_library

    def find_library_patch(name):
        if name == "magic":
            return str(libmagic_file)
        return ctypes_find_library(name)

    ctypes.util.find_library = find_library_patch

    import magic as pymagic

    magic_version = pymagic.version()
    if magic_version != expected_version:
        raise RuntimeError(
            f"Preloaded libmagic version is {magic_version}, but {expected_version} was expected"
        )

    get_magic = pymagic.Magic(mime=False, magic_file=str(database_file))
    get_mime = pymagic.Magic(mime=True, magic_file=str(database_file))
else:
    import magic as pymagic

    get_magic = pymagic.Magic(mime=False)
    get_mime = pymagic.Magic(mime=True)


def magic_from_content(content, mime):
    return (get_mime if mime else get_magic).from_buffer(content)


from karton.core.test import ConfigMock, KartonBackendMock

from karton.classifier import Classifier


@pytest.fixture(scope="class")
def karton_classifier(request):
    def _magic_from_content(_, content, mime):
        return magic_from_content(content, mime)

    classifier = Classifier(
        magic=magic_from_content, config=ConfigMock(), backend=KartonBackendMock()
    )
    request.cls.magic_from_content = _magic_from_content
    request.cls.karton = classifier
