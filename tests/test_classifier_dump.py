import pytest
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_dump_vhd(self):
        resource = mock_resource("dump.vhd")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "dump",
                "extension": "vhd",
                "mime": "application/x-virtualbox-vhd",
            },
            payload={
                "sample": resource,
                "tags": ["dump:vhd"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_dump_gif(self):
        resource = mock_resource("dump.gif")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "dump",
                "extension": "gif",
                "mime": "image/gif",
            },
            payload={
                "sample": resource,
                "tags": ["dump:gif"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_dump_jpg(self):
        resource = mock_resource("dump.jpg")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "dump",
                "extension": "jpg",
                "mime": "image/jpeg",
            },
            payload={
                "sample": resource,
                "tags": ["dump:jpg"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_dump_png(self):
        resource = mock_resource("dump.png")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "dump",
                "extension": "png",
                "mime": "image/png",
            },
            payload={
                "sample": resource,
                "tags": ["dump:png"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
