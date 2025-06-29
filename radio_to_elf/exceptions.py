class BadFileError(Exception):
    def __init__(self, message):
        super(BadFileError, self).__init__(message)


class FileParsingError(Exception):
    def __init__(self, message):
        super(FileParsingError, self).__init__(message)


class SectionOverlapError(Exception):
    def __init__(self, message):
        super(SectionOverlapError, self).__init__(message)

class DanglingSymbolError(Exception):
    def __init__(self, message):
        super(DanglingSymbolError, self).__init__(message)