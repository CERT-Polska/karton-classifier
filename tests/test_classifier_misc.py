import pytest
from karton.core import Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

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
                "mime": "text/plain",
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
                "mime": "text/html",
            },
            payload={
                "sample": resource,
                "tags": ["misc:html"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
