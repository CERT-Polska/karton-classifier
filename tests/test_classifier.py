from unittest.mock import MagicMock

import pytest
from karton.core import Resource, Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from karton.classifier import Classifier

from .mock_helper import mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process(self):
        resource = Resource("file.txt", b"ffafafffa\nfafafafa", sha256="sha256")
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
                "magic": "ASCII text",
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_unknown_file(self):
        resource = Resource("file.txt", b"\x00", sha256="sha256")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "unrecognized",
                "origin": "karton.classifier",
                "kind": "unknown",
                "quality": "high",
            },
            payload={
                "sample": resource,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_error(self):
        m = MagicMock()
        m.side_effect = Exception("unknown error")
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.txt", b"ffafafffa", sha256="sha256")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "unrecognized",
                "origin": "karton.classifier",
                "kind": "unknown",
                "quality": "high",
            },
            payload={
                "sample": resource,
            },
        )
        self.assertTasksEqual(res, [expected])
