#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    from pyglossary import Glossary

Glossary.init()
glos = Glossary()
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeTemporaryFile('', all_data=True, as_bytes=True) as f:
            glos.convert(f, outputFilename="/dev/null", outputFormat="Tabfile")
    except ValueError:
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
