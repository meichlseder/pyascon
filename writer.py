#!/usr/bin/env python3

"""
Writers for output test vectors in Text and JSON formats.
"""
from __future__ import annotations

from typing import Type, Optional, Self, overload, override
from types import TracebackType
from abc import ABC, abstractmethod

class GenericWriter(ABC):
    """
    GenericWriter used as a base class for all writers for better typing.
    """
    @abstractmethod
    def __enter__(self) -> Self:
        pass

    @abstractmethod
    def __exit__(self, stype: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        pass

    @overload
    @abstractmethod
    def append(self, label: str, value: bytes, length: Optional[int]) -> None: ...

    @overload
    @abstractmethod
    def append(self, label: str, value: int, length: None) -> None: ...

    @abstractmethod
    def append(self, label: str, value: bytes|int, length: Optional[int] = None) -> None:
        pass

    @abstractmethod
    def open(self) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

class TextWriter(GenericWriter):
    """
    TextWriter produces an array of key-value objects.
    """

    def __init__(self, filename: str) -> None:
        self.fp = open(filename + ".txt", "w")
        self.is_open = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, stype: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        self.fp.close()

    @overload
    def append(self, label: str, value: bytes, length: Optional[int] = None) -> None: ...
    @overload
    def append(self, label: str, value: int, length: None = None) -> None: ...
    def append(self, label: str, value: bytes|int, length: Optional[int] = None) -> None:
        assert self.is_open, "cannot append if not open yet"
        if length is not None:
            assert isinstance(value, bytes), "length can only be specified for value of type bytes"
            assert len(value) >= length
            value_fmt = value[:length].hex().upper()
        else:
            assert isinstance(value, int)
            value_fmt = f"{value}"

        self.fp.write("{} = {}\n".format(label, value_fmt))

    def open(self) -> None:
        assert not self.is_open, "cannot open twice"
        self.is_open = True

    def close(self) -> None:
        assert self.is_open, "cannot close if not open first"
        self.fp.write("\n")
        self.is_open = False


class JSONWriter(GenericWriter):
    """
    JSONWriter produces an array of JSON objects.
    """

    def __init__(self, filename: str) -> None:
        self.level = 1
        self.fp = open(filename + ".json", "w")
        self.has_item = False
        self.tab = " " * 2
        self.comma = lambda: "," * self.has_item
        self.ws = lambda: "\n" * \
            (self.level > 0 or self.has_item) + self.tab * self.level
        self.fp.write("[")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, stype: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        self.level -= 1
        self.fp.write("{}]\n".format(self.ws()))
        self.fp.close()

    @overload
    def append(self, label: str, value: bytes, length: Optional[int] = None) -> None: ...
    @overload
    def append(self, label: str, value: int, length: None=None) -> None: ...

    @override
    def append(self, label: str, value: bytes|int, length: Optional[int] = None):
        if length is not None:
            assert isinstance(value, bytes), "length can only be specified for value of type bytes"
            assert len(value) >= length
            value_fmt = '"{}"'.format(value[:length].hex().upper())
        else:
            assert isinstance(value, int)
            value_fmt = f"{value}"
        self.fp.write('{}{}"{}": {}'.format(
            self.comma(), self.ws(), label, value_fmt))
        self.has_item = True

    def open(self) -> None:
        assert (self.level > 0 or not self.has_item)
        self.fp.write("{}{}{{".format(self.comma(), self.ws()))
        self.level += 1
        self.has_item = False

    def close(self) -> None:
        assert (self.level > 0 or not self.has_item)
        self.level -= 1
        self.fp.write("{}}}".format(self.ws()))
        self.has_item = True


class MultipleWriter(GenericWriter):
    """
    Merge multiple writers to ease invocation.
    """

    def __init__(self, filename: str) -> None:
        self.writers: list[GenericWriter] = [JSONWriter(filename), TextWriter(filename)]

    def __enter__(self) -> Self:
        for w in self.writers:
            w.__enter__()
        return self

    def __exit__(self, stype: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        for w in self.writers:
            w.__exit__(stype, value, traceback)

    def open(self) -> None:
        for w in self.writers:
            w.open()

    @overload
    def append(self, label: str, value: bytes, length: Optional[int] = None) -> None: ...
    @overload
    def append(self, label: str, value: int, length: None = None) -> None: ...

    @override
    def append(self, label: str, value: bytes|int, length: Optional[int] = None) -> None:
        for w in self.writers:
            if isinstance(value, bytes):
                w.append(label, value, length)

    def close(self) -> None:
        for w in self.writers:
            w.close()


if __name__ == "__main__":
    with MultipleWriter("demo") as writer:
        writer.open()
        writer.append("Hello", 101)
        writer.close()
