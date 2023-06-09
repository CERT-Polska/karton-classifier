import pytest
from unittest.mock import ANY
from karton.core import Task
from karton.core.test import KartonTestCase

from .mock_helper import mock_resource, mock_task


@pytest.mark.usefixtures("karton_classifier")
class TestClassifier(KartonTestCase):
    def test_process_document_doc(self):
        resource = mock_resource("document.doc")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "doc",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:doc"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_docx(self):
        resource = mock_resource("document.docx")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "docx",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:docx"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_pdf(self):
        resource = mock_resource("document.pdf")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "pdf",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:pdf"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_rtf(self):
        resource = mock_resource("document.rtf")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "rtf",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:rtf"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_xls(self):
        resource = mock_resource("document.xls")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "xls",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:xls"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_xlsx(self):
        resource = mock_resource("document.xlsm")
        magic = self.magic_from_content(resource.content, mime=False)
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": ANY,
                "extension": "xlsx",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["document:win32:xlsx"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
