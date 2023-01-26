import pytest
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_script_win32_js(self):
        resource = mock_resource("script.js")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "js",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:js"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_jse(self):
        resource = mock_resource("script.jse")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "application/octet-stream",
                "extension": "jse",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:jse"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_ps1(self):
        resource = mock_resource("script.ps1")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "ps1",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:ps1"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_vbs(self):
        resource = mock_resource("script.vbs")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "vbs",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:vbs"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_php(self):
        resource = mock_resource("script.php")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/x-php",
                "extension": "php",
            },
            payload={
                "sample": resource,
                "tags": ["script:php"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_bash(self):
        resource = mock_resource("script.bash")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/x-shellscript",
                "extension": "sh",
            },
            payload={
                "sample": resource,
                "tags": ["script:sh"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_perl(self):
        resource = mock_resource("script.pl")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/x-perl",
                "extension": "pl",
            },
            payload={
                "sample": resource,
                "tags": ["script:pl"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_python(self):
        resource = mock_resource("script.py")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/x-python",
                "extension": "py",
            },
            payload={
                "sample": resource,
                "tags": ["script:py"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_ruby(self):
        resource = mock_resource("script.rb")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/x-ruby",
                "extension": "rb",
            },
            payload={
                "sample": resource,
                "tags": ["script:rb"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_script(self):
        resource = mock_resource("script.scpt")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "application/octet-stream",
                "extension": "scpt",
            },
            payload={
                "sample": resource,
                "tags": ["script:scpt"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
