from abc import ABC, abstractmethod


class Unpacker(ABC):

    @abstractmethod
    def get_format_name(self) -> str:
        pass

    @abstractmethod
    def check_can_unpack(self, data: bytes) -> bool:
        pass

    @abstractmethod
    def unpack(self, data: bytes) -> bytes:
        pass

