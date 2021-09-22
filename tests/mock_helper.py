import pathlib
from karton.core import Resource, Task

def mock_resource(filename: str, content: bytes) -> Resource:
    return Resource(filename, content, sha256="sha256")


def mock_task(resource: Resource) -> Task:
    task = Task(
        {
            "type": "sample",
            "kind": "raw",
        }
    )
    task.add_payload("sample", resource)
    return task
