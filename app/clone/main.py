"""
Step 1: Discover refs
    By sending a GET request to `C: GET $GIT_URL/info/refs?service=git-upload-pack HTTP/1.0`
Step 2: Negotiation bit, I really only need to send want requests. 
"""

import enum
import hashlib
import logging
import os
import shutil
import zlib
from dataclasses import dataclass
from typing import List, Set, Tuple, Type
from urllib.parse import urljoin

import requests
from typing_extensions import Self

TEST_GIT_URL = "https://github.com/Josh596/Weather-App.git"
# https://gitlab.com/beku.skrillex/jp_project
SUPPORTED_CAPABILITIES = [
    "side-band-64k",
]

OBJECTS_DIR = ".git/objects"
logging.basicConfig(encoding="utf-8", level=logging.INFO)


def init(parent_dir):
    os.chdir(parent_dir)
    if os.path.exists(".git"):
        shutil.rmtree(os.path.join(parent_dir, ".git"), ignore_errors=True)
        # raise Exception("Directory is already a git repository")
    os.mkdir(".git")
    os.mkdir(OBJECTS_DIR)
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    print("Initialized git directory")


def convert_path_to_absolute(path):
    if path[-1] != "/":
        path += "/"

    return path


@dataclass
class PktLine:
    full_content: str

    def content(self):
        content = self.full_content[4:].strip("\n")

        return content

    @classmethod
    def from_data(cls, content: str, add_lf: bool = True) -> Self:
        data = content

        if add_lf:
            data += "\n"
            # data += "\x00multi_ack side-band-64k ofs-delta\n"

        # Get length and convert to base16
        length = len(data) + 4
        length_b16 = hex(length).replace("0x", "00")
        print(length_b16, "Lenth")

        data = f"{length_b16:04}{data}"

        return PktLine(data)


@dataclass
class Ref:
    id_: str
    name: str


def get_pkt_line_from_response(data: str) -> List[PktLine]:
    first_packet, others = data.split("\n", maxsplit=1)

    _, data, _ = others.split("0000")
    data_split = data.splitlines(keepends=True)

    packets = [PktLine(first_packet + "\n")]
    packets.extend([PktLine(pkt) for pkt in data_split])

    return packets


def parse_refs_from_response(
    response: str, service: str = "git-upload-pack"
) -> Tuple[List[Ref], Set[str]]:
    pkt_lines = get_pkt_line_from_response(response)

    # Verify that first pkt-line is # service=$servicename.
    first_pkt = pkt_lines.pop(0)
    assert first_pkt.content() == f"# service={service}"

    refs = []
    capabilities = []
    for index, line in enumerate(pkt_lines):

        if index == 0:
            capabilities.extend(
                line.content()
                .removesuffix("\n")
                .split("\x00", maxsplit=1)[1]
                .split(" ")
            )

        data = "".join(line.content().split("\x00", maxsplit=1)[0])
        id_, name = data.split(" ")
        refs.append(Ref(id_, name))

    return refs, set(capabilities)


def discover_refs(
    git_url: str, service: str = "git-upload-pack"
) -> Tuple[List[Ref], Set[str]]:
    url = urljoin(git_url, "info/refs")
    r = requests.get(url=url, params={"service": service})
    refs, capabilities = parse_refs_from_response(r.text, service)

    return refs, capabilities


def get_pack(git_url: str, dir: str):
    refs, capabilities = discover_refs(git_url, "git-upload-pack")
    advertised = set([ref.id_ for ref in refs])
    common = {}
    want = set().union(advertised)

    # want_list = [PktLine.from_data(f"want {ref}").full_content for ref in want]
    want_list = []
    for index, ref in enumerate(want):

        content = f"want {ref}"
        if index == 0:
            content = content.removesuffix("\n")
            supported_capabilities = " ".join(
                list(capabilities.intersection(SUPPORTED_CAPABILITIES))
            )
            content += f" {supported_capabilities}\n"

        want_list.append(PktLine.from_data(content).full_content)
    url = urljoin(git_url, "git-upload-pack")

    data: List[str] = []
    data.extend(want_list)
    data.append("0000")
    data.append("0009done\n")

    def data_gen():
        for item in data:

            yield item

        yield "0000"
        yield "0009done\n"

    s = requests.Session()

    with s.post(
        url,
        data=data_gen(),
        stream=True,
        allow_redirects=True,
        headers={
            "Content-Type": "application/x-git-upload-pack-request",
            "Accept": "application/x-git-upload-pack-result",
            "Connection": "keep-alive",
        },
    ) as r:
        # print(r.headers)
        if r.status_code == 200:
            error_occured = False
            init(parent_dir=dir)
            os.mkdir(os.path.join(dir, ".git", "objects", "pack"))
            location = os.path.join(dir, ".git", "objects", "pack", "pack.pack")
            with open(location, "wb+") as pack_file:
                leftover = b""
                acknowledgement = ""
                for chunk in r.iter_content(65520, decode_unicode=False):
                    chunk = leftover + chunk
                    leftover = b""
                    if error_occured:
                        shutil.rmtree(os.path.join(dir, ".git"), ignore_errors=True)
                        break

                    while chunk:
                        # Not enough data to get length, save for next_iteration, or exit, not sure
                        if len(chunk) < 4:
                            leftover = chunk
                            break
                        packet_length = int(chunk[:4], 16)

                        if packet_length == 0:
                            leftover = b""
                            break

                        if len(chunk) < packet_length:
                            leftover = chunk
                            break

                        data = chunk[5:packet_length]
                        if not acknowledgement:
                            data = chunk[4:packet_length]
                            leftover = data[packet_length:]
                            acknowledgement = data
                            break

                        sideband = chunk[4]

                        if sideband == 1:
                            pack_file.write(data)
                        elif sideband == 2:
                            logging.info(
                                f"Progesss: {data.decode('utf-8')}",
                            )
                        elif sideband == 3:
                            logging.error(
                                f"Error: {data.decode('utf-8')}",
                            )
                            error_occured = True
                            break
                        chunk = chunk[packet_length:]
            unpack_pack_file(location)

        else:
            print("Failed to get packfile:", r.status_code, r.text)


@dataclass
class GitObject:
    content: str
    index: int
    length: int

    def hash(self):
        return hashlib.sha1(self.content).hexdigest()


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
    pass


class Tree(GitObject):
    pass


class Blob(GitObject):
    pass


class Tag(GitObject):
    pass


@dataclass
class GitRef(GitObject):
    base_object: GitObject


def unpack_pack_file(location: str):
    print(location)
    objects: List[GitObject] = []
    with open(location, "rb") as pack_file:
        data = pack_file.read()

        # ======================= HEADER ==========================
        signature1 = data[:4]
        if signature1 != b"PACK":
            raise Exception("Invalid Pack File")

        version_number = int.from_bytes(data[4:8], "big")
        logging.info(f"Pack File Version Number: {version_number}")

        no_of_objects = int.from_bytes(data[8:12], "big")
        logging.info(f"Total number of objects: {no_of_objects}")

        # ======================= HEADER FINISHED ==========================

        # ======================= CHECKSUM ==========================
        checksum = data[-20:].hex()
        logging.info(f"Checksum: {checksum}")

        # ======================= CHECKSUM FINISHED ==========================

        # ======================= DECODING DATA ==========================

        unread_data = data[12:-20]
        # print(len(unread_data), "Unread")
        while unread_data:

            length_bytes = []
            object_type = None
            # Get the length, type and compressed data
            for index, byte_ in enumerate(unread_data):
                mask = 0b1111111
                if index == 0:
                    # print(byte_, bin(byte_))
                    d = byte_ & 0b1110000
                    d = d >> 4
                    # print(d, bin(d), "D")
                    object_type = ObjectType.from_value(d)
                    mask = 0b1111

                length_bytes.append(byte_ & mask)
                if byte_ < 128:  # so MSB is not set
                    break

            length_bytes_reversed = reversed(length_bytes)
            length_bits = "".join(format(digit, "b") for digit in length_bytes_reversed)
            length_object = int(length_bits, 2)

            content = unread_data[len(length_bytes) :]

            if object_type not in [ObjectType.REF_DELTA, ObjectType.OFS_DELTA]:
                # Decompress content
                content = zlib.decompress(content)

                data_length = len(zlib.compress(content))

                # print(length_bytes, data_length)
                unread_data = unread_data[len(length_bytes) + data_length :]

                if not objects:
                    index = 0
                else:
                    index = objects[-1].index + objects[-1].length
                objects.append(
                    object_type.create_object()(
                        content=content, index=index, length=data_length
                    )
                )
            else:
                # DELTIFIED VERSIONS
                if object_type == ObjectType.REF_DELTA:
                    name_base_object = content[:20].hex()
                    content = content[20:]

                    # Decompress content
                    content = zlib.decompress(content)

                    data_length = len(zlib.compress(content))

                    # print(length_bytes, data_length)
                    unread_data = unread_data[len(length_bytes) + data_length + 20 :]

                    # Get parent object
                    for object in objects:
                        if object.hash() == name_base_object:
                            index = objects[-1].index + objects[-1].length
                            objects.append(
                                object_type.create_object()(
                                    content=content,
                                    base_object=object,
                                    index=index,
                                    length=data_length,
                                )
                            )

                if object_type == ObjectType.OFS_DELTA:
                    print("OFS")
                    # I'll need to store each object start index and length

                    offset_bytes = []
                    # Get the length, type and compressed data
                    for byte_ in unread_data:
                        mask = 0b1111111

                        length_bytes.append(byte_ & mask)
                        if byte_ < 128:  # so MSB is not set
                            break

                    offset_bytes_reversed = reversed(length_bytes)
                    offset_bits = "".join(
                        format(digit, "b") for digit in length_bytes_reversed
                    )

                    offset = int(offset_bits, 2)

                    base_object_index = objects[-1].index + objects[-1].length - offset

                    content = content[len(offset_bytes) :]
                    # Decompress content
                    content = zlib.decompress(content)

                    data_length = len(zlib.compress(content))

                    # print(length_bytes, data_length)

                    for object in objects:
                        if object.index == base_object_index:
                            objects.append(
                                object_type.create_object()(
                                    content=content,
                                    base_object=object,
                                    index=index,
                                    length=data_length,
                                )
                            )

                    unread_data = unread_data[
                        len(length_bytes) + data_length + len(offset_bytes) :
                    ]
                    pass

            # TODO: HANDLE DELTIFIED OBJECT
            pass

    print("All objects", len(objects), [type(object) for object in objects])
    # For each object in no_objects
    # Get the length
    # Get the data


def clone(git_url: str, location: str):

    git_url = convert_path_to_absolute(git_url)
    dir = "/Users/Josh/Desktop/Personal-Projects/git_test"
    # Create .git folder, raise error if it already exist
    # discover_refs(git_url, "git-upload-pack")
    # get_pack(git_url, dir)
    unpack_pack_file(
        location="/Users/Josh/Desktop/Personal-Projects/git_test/.git/objects/pack/pack.pack"
    )

    #


if __name__ == "__main__":
    clone(TEST_GIT_URL, ".")
