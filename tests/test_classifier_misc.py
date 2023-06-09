import pytest
from unittest.mock import ANY
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_misc_ascii(self):
        resource = mock_resource("misc.ascii")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "ascii",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:ascii"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_html(self):
        resource = mock_resource("misc.html")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "html",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:html"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_csv(self):
        resource = mock_resource("misc.csv")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "csv",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:csv"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_gif(self):
        resource = mock_resource("misc.gif")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "misc",
                "extension": "gif",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:gif"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_jpg(self):
        resource = mock_resource("misc.jpg")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "misc",
                "extension": "jpg",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:jpg"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_png(self):
        resource = mock_resource("misc.png")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "misc",
                "extension": "png",
                "mime": ANY,
            },
            payload={
                "sample": resource,
                "tags": ["misc:png"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
