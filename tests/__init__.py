import os
import json

from karton.core import Task
from karton.core.test import KartonTestCase, TestResource

from karton.classifier import Classifier


class ClassifierTestCase(KartonTestCase):
    karton_class = Classifier

    def test_works_as_expected(self):
        self.maxDiff = None
        for testcase in os.listdir("tests/testdata"):
            print(testcase)
            if not testcase.endswith('.json'):
                continue

            testcase_config = testcase
            testcase_content = testcase_config.replace('.json', '')

            with self.subTest(testcase):
                with open(f"tests/testdata/{testcase_config}", "rb") as f:
                    expected = json.load(f)
                with open(f"tests/testdata/{testcase_content}", "rb") as f:
                    content = f.read()

                sample = TestResource(testcase_content, content)
                task = Task({
                    "type": "sample",
                    "kind": "raw"
                }, payload={
                    "sample": sample,
                    "extraction_level": 999,
                })

                payload = {
                    "sample": sample,
                    "extraction_level": 999,
                }
                if expected.get("payload"):
                    payload.update(expected["payload"])

                res = self.run_task(task)
                self.assertTasksEqual(res, [Task(expected["headers"], payload)])
