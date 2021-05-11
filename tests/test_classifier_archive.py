from karton.core import Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from .mock_helper import mock_classifier, mock_resource, mock_task


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_archive_7z(self):
        magic, mime = "7-zip archive data...", "application/x-7z-compressed"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.7z")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "7z",
            },
            payload={
                "sample": resource,
                "tags": ["archive:7z"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_ace(self):
        magic, mime = "ACE archive data version 20...", "application/octet-stream"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.ace")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "ace",
            },
            payload={
                "sample": resource,
                "tags": ["archive:ace"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_bz2(self):
        magic, mime = "bzip2 compressed data...", "application/x-bzip2"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.bz2")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "bz2",
            },
            payload={
                "sample": resource,
                "tags": ["archive:bz2"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_cab(self):
        magic, mime = (
            "Microsoft Cabinet archive data...",
            "application/vnd.ms-cab-compressed",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.cab")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "cab",
            },
            payload={
                "sample": resource,
                "tags": ["archive:cab"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_cab_no_extension(self):
        magic, mime = (
            "Microsoft Cabinet archive data...",
            "application/vnd.ms-cab-compressed",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "cab",
            },
            payload={
                "sample": resource,
                "tags": ["archive:cab"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_gz(self):
        magic, mime = "gzip compressed data...", "application/gzip"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.gz")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "gz",
            },
            payload={
                "sample": resource,
                "tags": ["archive:gz"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_iso(self):
        magic, mime = (
            "ISO 9660 CD-ROM filesystem data...",
            "application/x-iso9660-image",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.iso")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "iso",
            },
            payload={
                "sample": resource,
                "tags": ["archive:iso"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_lz(self):
        magic, mime = "lzip compressed data...", "application/x-lzip"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.lz")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "lz",
            },
            payload={"sample": resource, "tags": ["archive:lz"], "magic": magic},
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_rar(self):
        magic, mime = "RAR archive data...", "application/x-rar"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.rar")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "rar",
            },
            payload={
                "sample": resource,
                "tags": ["archive:rar"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_tar(self):
        magic, mime = "POSIX tar archive", "application/x-tar"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.tar")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "tar",
            },
            payload={
                "sample": resource,
                "tags": ["archive:tar"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_udf(self):
        magic, mime = "UDF filesystem data...", "application/x-iso9660-image"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.udf")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "udf",
            },
            payload={
                "sample": resource,
                "tags": ["archive:udf"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_xz(self):
        magic, mime = "XZ compressed data", "application/x-xz"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.xz")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "xz",
            },
            payload={
                "sample": resource,
                "tags": ["archive:xz"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_zip(self):
        magic, mime = "Zip archive data", "application/zip"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.zip")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": mime,
                "extension": "zip",
            },
            payload={
                "sample": resource,
                "tags": ["archive:zip"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
