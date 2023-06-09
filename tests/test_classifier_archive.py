import pytest
from unittest.mock import ANY
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_archive_7z(self):
        resource = mock_resource("archive.7z")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.ace")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.bz2")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.cab")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
                "extension": "cab",
            },
            payload={
                "sample": resource,
                "tags": ["archive:cab"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_cab_with_extension(self):
        resource = mock_resource("archive.cab", with_name=True)
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.gz")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.iso")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.lz")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
                "extension": "lz",
            },
            payload={"sample": resource, "tags": ["archive:lz"], "magic": magic},
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_rar(self):
        resource = mock_resource("archive.rar")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.tar")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.udf")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.xz")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
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
        resource = mock_resource("archive.zip")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": ANY,
                "extension": "zip",
            },
            payload={
                "sample": resource,
                "tags": ["archive:zip"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_vhd(self):
        resource = mock_resource("dump.vhd")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "extension": "vhd",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["archive:vhd"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

