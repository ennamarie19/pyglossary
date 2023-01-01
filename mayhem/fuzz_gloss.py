#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers
import io
from contextlib import contextmanager

with atheris.instrument_imports():
    from pyglossary import Glossary
@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

Glossary.init()
glos = Glossary()
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeTemporaryFile('', all_data=True, as_bytes=True) as f, nostdout():
            glos.convert(inputFilename=f, inputFormat="", outputFilename="/dev/null", outputFormat="")
    except (UnicodeDecodeError, ValueError, PermissionError):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
