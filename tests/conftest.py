import pathlib

tests_dir = pathlib.Path(__file__).parent

# Actual conftest.py goes there
# pymagic must be patched before any imports occur

from karton.classifier import Classifier
import pytest



@pytest.fixture(scope="class")
def karton_classifier(request):
    def _magic_from_content(self, content):
        # Function called by tests to get magic
        return self.karton._magic(content)[0]

    request.cls.karton_class = Classifier
    request.cls.magic_from_content = _magic_from_content
