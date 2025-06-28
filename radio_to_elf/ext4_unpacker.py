import os
import logging
import ext4

from io import BytesIO

from unpacker import Unpacker

from exceptions import BadFileError, FileParsingError


class Ext4Unpacker(Unpacker):
    READ_GRANULARITY = 0x1000

    def get_format_name(self) -> str:
        return "EXT4"

    def check_can_unpack(self, data: bytes) -> bool:
        return self.check_is_ext4(data) or self.check_is_ext4(b"\x00" * 1024 + data)

    def unpack(self, data: bytes) -> bytes:
        if not self.check_is_ext4(data):
            data = b"\x00" * 1024 + data

        with BytesIO(data) as f:
            volume = ext4.Volume(f)
            root_dir = b"."

            dirs = [root_dir]
            files = []
            while len(dirs) > 0:
                next_dirs = []
                for directory in dirs:
                    for child in volume.inode_at(directory).opendir():
                        entry, entry_type = child
                        full_path = os.path.join(directory, entry.name)

                        if entry.name in [b".", b"..", b"lost+found"]:  # The blacklist
                            continue

                        if entry_type == ext4.enum.EXT4_FT.DIR:
                            next_dirs.append(full_path)
                        elif entry_type == ext4.enum.EXT4_FT.REG_FILE:
                            files.append(full_path)

                dirs = next_dirs

            modem_files = [file.decode()
                           for file in files if file.endswith(b"modem.bin")]

            logging.info(f"Found {len(modem_files)} modem file(s)")
            logging.debug(f"Modem files: {modem_files}")

            if len(modem_files) == 0:
                raise BadFileError(
                    "EXT4 filesystem image does not contain a modem.bin file")

            modem_file_path = modem_files[0]
            modem_file = volume.inode_at(modem_file_path)
            modem_ext4_reader = modem_file.open()
            modem_file_size = len(modem_ext4_reader)

            logging.debug(
                f"Extracting modem file at \"{modem_file_path}\" of size {modem_file_size} bytes")

            modem_io = BytesIO()

            written = 0
            while written < modem_file_size:
                chunk = modem_ext4_reader.read(
                    min(self.READ_GRANULARITY, modem_file_size - written))
                modem_io.write(chunk)
                written += len(chunk)

            modem_io.seek(0)
            return modem_io.read()

    def check_is_ext4(self, data: bytes) -> bool:
        with BytesIO(data) as f:
            try:
                ext4.Volume(f)

                return True
            except ext4.struct.MagicError:
                return False

        # with BytesIO(data) as f:
        #     with tarfile.open(mode='r', fileobj=f) as tf:
        #         for member in tf.getmembers():
        #             if (member.isfile() or member.islink()) and member.name.endswith(".ext4"):
        #                 reader = tf.extractfile(member)
        #                 return reader.read()
        #             else:
        #                 logging.info(
        #                     f"Skipping unwanted tar entry \"{member.name}\"")
