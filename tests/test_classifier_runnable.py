import pytest
from unittest.mock import ANY
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_runnable_android_dex(self):
        resource = mock_resource("runnable.dex")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "dex",
                "platform": "android",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:android:dex"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_linux(self):
        resource = mock_resource("runnable.spc")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "elf",
                "platform": "openbsd",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:openbsd:elf"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_dll(self):
        resource = mock_resource("runnable.dll")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "dll",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:dll"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_exe(self):
        resource = mock_resource("runnable.exe")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "exe",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:exe"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_jar(self):
        resource = mock_resource("runnable.jar")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "jar",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:jar"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_lnk(self):
        resource = mock_resource("runnable.lnk")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "lnk",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:lnk"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_msi(self):
        resource = mock_resource("runnable.msi")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "msi",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:msi"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_swf(self):
        resource = mock_resource("runnable.swf")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "swf",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:swf"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win64_dll(self):
        resource = mock_resource("runnable.dll64")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "dll",
                "platform": "win64",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win64:dll"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win64_exe(self):
        resource = mock_resource("runnable.exe64")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": ANY,
                "extension": "exe",
                "platform": "win64",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win64:exe"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
