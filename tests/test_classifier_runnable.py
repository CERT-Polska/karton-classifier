from karton.core import Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from .mock_helper import mock_classifier, mock_resource, mock_task


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_runnable_android_dec(self):
        magic, mime = "Dalvik dex file version 035", "application/octet-stream"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = "ELF 32-bit MSB executable...", "application/x-executable"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
                "platform": "linux",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:linux"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_dll(self):
        magic, mime = (
            "PE32 executable (DLL) (console) Intel 80386...",
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = (
            "PE32 executable (GUI) Intel 80386 Mono/.Net assembly...",
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = "Zip archive data...", "application/zip"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.jar")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = "MS Windows shortcut...", "application/octet-stream"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.lnk")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = (
            "Composite Document File V2 Document, MSI Installer...",
            "application/x-msi",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.msi")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = (
            "Macromedia Flash data (compressed)...",
            "application/x-shockwave-flash",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.swf")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = "PE32+ executable (DLL) (GUI) x86-64...", "application/x-dosexec"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
        magic, mime = "PE32+ executable (console) x86-64...", "application/x-dosexec"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "runnable",
                "mime": mime,
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
