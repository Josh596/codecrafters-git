import enum
import hashlib
import os
import zlib
from dataclasses import dataclass
from typing import Optional, Type

from typing_extensions import Self

from .constants import OBJECTS_DIR
from .utils import get_bit, get_length


class GitObject:

    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
        object_type: str = "",
    ):
        self.content = content
        self.index = index
        self.length = length
        self.object_type = object_type
        self._name = ""
        self.parent: Optional[Self] = None
        self.is_dir = False

    def hash(self):
        header = f"{self.object_type} {len(self.content)}\0"
        sha1_hash = hashlib.sha1(header.encode() + self.content).hexdigest()
        return sha1_hash

    def write(self):
        sha_hash = self.hash()
        compressed_content = zlib.compress(self.content)

        file_objects_dir = os.path.join(OBJECTS_DIR, sha_hash[:2])
        os.mkdir(file_objects_dir)
        with open(os.path.join(file_objects_dir, sha_hash[2:]), "+wb") as object_file:
            object_file.write(compressed_content)

        return sha_hash

    @property
    def name(self) -> str:
        if not self._name and self.parent:
            raise Exception("Path not yet set")

        return self._name

    @name.setter
    def name(self, filename: str):
        self._name = filename

    def full_path(self):
        # Construct path from parents
        # obj = self
        path = ""
        # paths = []
        if self.parent:
            path = os.path.join(self.parent.full_path(), self.name)
        # while obj:
        #     paths.append(obj.name)
        #     path = os.path.join(obj.name, path)

        #     obj = obj.parent
        # print(path, self.name, self.parent, "Object path ogghhhh", sep="--")
        return path

    def save(self):

        full_path = self.full_path()
        print(full_path, "Full path")
        if not self.name:
            return
        if self.is_dir:
            os.makedirs(full_path)
        else:
            # File mode to clear file first
            with open(full_path, "wb") as file:
                file.write(self.content)


class ObjectType(enum.Enum):
    COMMIT = enum.auto()
    TREE = enum.auto()
    BLOB = enum.auto()
    TAG = enum.auto()
    OFS_DELTA = enum.auto()
    REF_DELTA = enum.auto()

    @classmethod
    def from_value(cls, val: int):
        OBJECT_MAPPING = {
            1: ObjectType.COMMIT,
            2: ObjectType.TREE,
            3: ObjectType.BLOB,
            4: ObjectType.TAG,
            6: ObjectType.OFS_DELTA,
            7: ObjectType.REF_DELTA,
        }

        obj = OBJECT_MAPPING.get(val)

        if not obj:
            raise Exception(f"Invalid value={val}")

        return obj

    # @classmethod
    def create_object(self) -> Type[GitObject]:
        # print(self, type(self), self.name)
        mapping = {
            ObjectType.COMMIT.name: Commit,
            ObjectType.TREE.name: Tree,
            ObjectType.BLOB.name: Blob,
            ObjectType.TAG.name: Tag,
            ObjectType.OFS_DELTA.name: GitRef,
            ObjectType.REF_DELTA.name: GitRef,
        }

        obj = mapping[self.name]

        return obj


class Commit(GitObject):
    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
    ):
        super().__init__(content, index, length, "commit")

    pass

    def save(self):
        pass


class Tree(GitObject):
    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
    ):
        super().__init__(content, index, length, "tree")
        self.is_dir = True

    pass


class Blob(GitObject):
    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
    ):
        super().__init__(content, index, length, "blob")

    pass


class Tag(GitObject):
    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
    ):
        super().__init__(content, index, length, "tag")

    def save(self):
        pass


@dataclass
class GitRef(GitObject):
    def __init__(
        self,
        content: bytes,
        index: int,
        length: int,
        base_object: GitObject,
    ):
        super().__init__(content, index, length, "ref")
        self.base_object = base_object
        self._content: bytes = content
        self.object_type = self.base_object.object_type
        self.is_dir = self.base_object.is_dir

    @property
    def content(self):
        print("==============Start=============\n")
        # source_length_bytes, tells us the length of the variable_length_integer, source_length tells us it's value
        source_length_bytes, source_length = get_length(self._content)
        # print(source_length, self.base_object.length, "COmparsion of length")
        target_length_in_bytes, target_length = get_length(
            self._content[source_length_bytes:]
        )
        print(source_length_bytes, target_length_in_bytes, "Bytees")

        data: bytes = self._content[source_length_bytes + target_length_in_bytes :]

        output = b""
        while data:
            # Copy instruction
            """
            Last four bits determine the offset
            """
            # Am I supposed to be working on the compressed or uncompressed texts?
            # Get instrustion
            if data[0] < 128:
                # Insert operation
                print("Insert ops")
                output += data[1 : data[0] + 1]
                data = data[1 + data[0] :]
            else:
                print("Copy ops")
                # Las
                # Copy operation
                instruction = data[0]

                # Get offset
                index = 1
                offset = ""
                length = ""
                for i in reversed(range(4, 8)):
                    if get_bit(instruction, i):
                        value = data[index]
                        index += 1
                    else:
                        value = 0
                    offset = format(value, "08b") + offset

                # Get length
                for i in reversed(range(1, 4)):
                    if get_bit(instruction, i):
                        value = data[index]
                        index += 1
                    else:
                        value = 0

                    length = format(value, "08b") + length
                print(offset, length, "Offset and Length", sep=">>>")
                offset = int(offset, 2)
                length = int(length, 2)

                if length == 0:
                    length = int("0x10000", 16)
                    length = 65536
                print(offset, length, "Offset and Length")
                output += self.base_object.content[offset : offset + length]

                data = data[index:]
        print(len(output), "Output Length")
        print(
            target_length,
            len(output),
            "COmparsion of Output length",
        )
        print("==============End=============\n")
        return output

    @content.setter
    def content(self, content: bytes):
        self._content = content
