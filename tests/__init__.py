import os

from karton2 import Task
from karton2.test import KartonTestCase, TestResource

from classifier import Classifier


class ClassifierTestCase(KartonTestCase):
    karton_class = Classifier

    def _single_file_test(
            self, name, content,
            kind=None, platform=None, extension=None
    ):
        sample = TestResource(name, content)
        task = Task({
            "type": "sample",
            "kind": "raw"
        }, payload={
            "sample": sample,
            "extraction_level": 999
        })
        results = self.run_task(task)
        if kind is None:
            self.assertTasksEqual(results, [])
        else:
            expected_headers = {
                "origin": "karton.classifier",
                "type": "sample",
                "stage": "recognized",
                "quality": "high",
                "kind": kind
            }
            if platform:
                expected_headers["platform"] = platform
            if extension:
                expected_headers["extension"] = extension
            self.assertTasksEqual(results, [
                Task(expected_headers, payload={
                    "sample": sample,
                    "extraction_level": 999
                })
            ])

    def test_works_as_expected(self):
        for testcase in os.listdir("tests/testdata"):
            with self.subTest(testcase):
                with open(f"tests/testdata/{testcase}", "rb") as f:
                    content = f.read()
                expected_tag, file_name = testcase.split("-", 1)
                tag_elements = expected_tag.split(":")
                headers = {
                    "kind": tag_elements[0]
                }
                if len(tag_elements) > 1:
                    if tag_elements[0] == "archive":
                        headers["extension"] = tag_elements[1]
                    else:
                        headers["platform"] = tag_elements[1]
                        if len(tag_elements) > 2:
                            headers["extension"] = tag_elements[2]
                self._single_file_test(
                    file_name, content, **headers
                )
