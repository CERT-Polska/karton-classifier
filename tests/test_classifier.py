import pytest
from unittest.mock import MagicMock

from karton.core import Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from karton.classifier import Classifier

from .mock_helper import mock_classifier, mock_resource, mock_task


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process(self):
        magic, mime = "ASCII text...", "text/plain"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.txt")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "ascii",
                "mime": mime,
            },
            payload={
                "sample": resource,
                "tags": ["misc:ascii"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_unknown(self):
        magic, mime = "", None
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "unrecognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "unknown",
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

        resource = mock_resource("file.txt")
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
