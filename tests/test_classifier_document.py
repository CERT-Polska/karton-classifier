from karton.core import Task
from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase

from .mock_helper import mock_classifier, mock_resource, mock_task


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_document_doc(self):
        magic, mime = "Composite Document File V2 Document...", "application/msword"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.doc")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
        magic, mime = (
            "Microsoft Word 2007+...",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.docx")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
        magic, mime = "PDF document...", "application/pdf"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.pdf")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
        magic, mime = "Rich Text Format data...", "text/rtf"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.rtf")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
        magic, mime = (
            "Composite Document File V2 Document...",
            "application/vnd.ms-excel",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.xls")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
        magic, mime = (
            "Microsoft Excel 2007+...",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.xlsx")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "document",
                "mime": mime,
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
