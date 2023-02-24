#!/usr/bin/env python3

"""
Writers for output test vectors in Text and JSON formats.
"""


class TextWriter:
    """
    TextWriter produces an array of key-value objects.
    """

    def __init__(self, filename):
        self.fp = open(filename + ".txt", "w")
        self.is_open = False

    def __enter__(self):
        return self

    def __exit__(self, stype, value, traceback):
        pass

    def append(self, label, value, length=None):
        assert self.is_open, "cannot append if not open yet"
        if length is not None:
            assert len(value) >= length
            value = value[:length].hex().upper()
        self.fp.write("{} = {}\n".format(label, value))

    def open(self):
        assert not self.is_open, "cannot open twice"
        self.is_open = True

    def close(self):
        assert self.is_open, "cannot close if not open first"
        self.fp.write("\n")
        self.is_open = False


class JSONWriter:
    """
    JSONWriter produces an array of JSON objects.
    """

    def __init__(self, filename):
        self.level = 1
        self.fp = open(filename + ".json", "w")
        self.has_item = False
        self.tab = " " * 2
        self.comma = lambda: "," * self.has_item
        self.ws = lambda: "\n" * \
            (self.level > 0 or self.has_item) + self.tab * self.level
        self.fp.write("[")

    def __enter__(self):
        return self

    def __exit__(self, stype, value, traceback):
        self.level -= 1
        self.fp.write("{}]\n".format(self.ws()))

    def append(self, label, value, length=None):
        if length is not None:
            assert len(value) >= length
            value = '"{}"'.format(value[:length].hex().upper())
        self.fp.write('{}{}"{}": {}'.format(
            self.comma(), self.ws(), label, value))
        self.has_item = True

    def open(self):
        assert (self.level > 0 or not self.has_item)
        self.fp.write("{}{}{{".format(self.comma(), self.ws()))
        self.level += 1
        self.has_item = False

    def close(self):
        assert (self.level > 0 or not self.has_item)
        self.level -= 1
        self.fp.write("{}}}".format(self.ws()))
        self.has_item = True


class MultipleWriter:
    """
    Merge multiple writers to ease invocation.
    """

    def __init__(self, filename):
        self.writers = [JSONWriter(filename), TextWriter(filename)]

    def __enter__(self):
        for w in self.writers:
            w.__enter__()
        return self

    def __exit__(self, stype, value, traceback):
        for w in self.writers:
            w.__exit__(stype, value, traceback)
            w.fp.close()

    def open(self):
        for w in self.writers:
            w.open()

    def append(self, label, value, length=None):
        for w in self.writers:
            w.append(label, value, length)

    def close(self):
        for w in self.writers:
            w.close()


if __name__ == "__main__":
    with MultipleWriter("demo") as writer:
        writer.open()
        writer.append("Hello", 101)
        writer.close()
