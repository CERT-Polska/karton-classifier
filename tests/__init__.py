import os

from karton.core import Task
from karton.core.test import KartonTestCase, TestResource

from karton.classifier import Classifier


class ClassifierTestCase(KartonTestCase):
    karton_class = Classifier

    def _single_file_test(
            self, name, content, tag,
            kind=None, platform=None, extension=None, stage="recognized"
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
                "stage": stage,
                "quality": "high",
                "kind": kind
            }
            if platform:
                expected_headers["platform"] = platform
            if extension:
                expected_headers["extension"] = extension

            payload = {
                "sample": sample,
                "extraction_level": 999,
            }
            if tag:
                payload["tags"] = [tag]

            self.assertTasksEqual(results, [Task(expected_headers, payload)])

    def test_works_as_expected(self):
        for testcase in os.listdir("tests/testdata"):
            with self.subTest(testcase):
                with open(f"tests/testdata/{testcase}", "rb") as f:
                    content = f.read()
                expected_tag, file_name = testcase.split("-", 1)
                tag_elements = expected_tag.split(":")

                # "misc" prefix is added only for mwdb compatibility
                if tag_elements[0] == "misc":
                    tag_elements = tag_elements[1:]

                headers = {
                    "kind": tag_elements[0],
                    'stage': "recognized",
                }
                if len(tag_elements) > 1:
                    if tag_elements[0] == "archive":
                        headers["extension"] = tag_elements[1]
                    elif (tag_elements[0] == "unknown"):
                        expected_tag = None
                        headers['stage'] = "unrecognized"
                    else:
                        headers["platform"] = tag_elements[1]
                        if len(tag_elements) > 2:
                            headers["extension"] = tag_elements[2]
                self._single_file_test(
                    file_name, content, expected_tag, **headers
                )
