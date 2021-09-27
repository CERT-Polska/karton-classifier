import pathlib

from karton.core import Resource, Task

tests_dir = pathlib.Path(__file__).parent


def mock_resource(filename: str, with_name=False) -> Resource:
    filepath = tests_dir / "testdata" / filename
    return Resource(
        filename if with_name else "file", filepath.read_bytes(), sha256="sha256"
    )


def mock_task(resource: Resource) -> Task:
    task = Task(
        {
            "type": "sample",
            "kind": "raw",
        }
    )
    task.add_payload("sample", resource)
    return task
