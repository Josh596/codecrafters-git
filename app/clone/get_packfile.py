import logging
import os
import shutil
import zlib
from dataclasses import dataclass
from optparse import Option
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
from typing_extensions import Self

from .objects import GitObject, ObjectType
from .utils import get_length, init

SUPPORTED_CAPABILITIES = [
    "side-band-64k",
]


@dataclass
class PktLine:
    full_content: str

    def content(self):
        content = self.full_content[4:].strip("\n")

        return content

    @classmethod
    def from_data(cls, content: str, add_lf: bool = True) -> "PktLine":
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

    data_: List[str] = []
    data_.extend(want_list)
    data_.append("0000")
    data_.append("0009done\n")

    def data_gen():
        for item in data_:

            yield item

        yield "0000"
        yield "0009done\n"

    s = requests.Session()

    with s.post(
        url,
        data=data_gen(),  # noqa
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
            output = []
            with open(location, "wb+") as pack_file:
                leftover = b""
                acknowledgement = b""
                for chunk in r.iter_content(65520, decode_unicode=False):
                    chunk: bytes
                    chunk = leftover + chunk
                    leftover = b""
                    if error_occured:
                        shutil.rmtree(os.path.join(dir, ".git"), ignore_errors=True)
                        break

                    while chunk:
                        print("Reading chunk")
                        # Not enough data to get length, save for next_iteration, or exit, not sure
                        if len(chunk) < 4:
                            leftover = chunk
                            break
                        try:
                            packet_length = int(chunk[:4], 16)
                        except Exception as e:
                            print(chunk)
                            # print(output[-1]) if output else ""
                            raise e

                        if packet_length == 0:
                            leftover = b""
                            break

                        if len(chunk) < packet_length:
                            leftover = chunk
                            break
                        # THIS IS DATA -  without SIDEBAND
                        # I think this should range from 5: packet_length-5
                        data: bytes = chunk[5:packet_length]
                        if not acknowledgement:
                            data = chunk[4:packet_length]
                            leftover = chunk[packet_length:]
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
                        output.append(data)
                        chunk = chunk[packet_length:]
            unpack_pack_file(location)

        else:
            print("Failed to get packfile:", r.status_code, r.text)


def unpack_pack_file(location: str) -> List[GitObject]:
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
            object_type: Optional[ObjectType] = None

            # Get the length, type and compressed data
            for index, byte_ in enumerate(unread_data):
                mask = 0b1111111
                bits_count = 7
                if index == 0:
                    # print(byte_, bin(byte_))
                    d = byte_ & 0b1110000
                    d = d >> 4
                    # print(d, bin(d), "D")
                    object_type = ObjectType.from_value(d)
                    mask = 0b1111
                    bits_count = 4

                length_bytes.append(format(byte_ & mask, f"0{bits_count}b"))
                if byte_ < 128:  # so MSB is not set
                    break

            length_bytes = len(length_bytes)

            # print(length_object, length_bits, b)
            content = unread_data[length_bytes:]

            if object_type not in [ObjectType.REF_DELTA, ObjectType.OFS_DELTA]:
                # Decompress content
                decompress_content = zlib.decompress(content)
                data_length = len(
                    zlib.compress(decompress_content)
                )  # Compressed data length
                total_length = length_bytes + data_length
                unread_data = unread_data[length_bytes + data_length :]

                if not objects:
                    index = 0
                else:
                    index = objects[-1].index + objects[-1].length

                if object_type:
                    objects.append(
                        object_type.create_object()(
                            content=decompress_content,
                            index=index,
                            length=data_length,
                        )
                    )
            else:
                # DELTIFIED VERSIONS
                if object_type == ObjectType.REF_DELTA:
                    name_base_object = content[:20].hex()
                    print(name_base_object)
                    content = content[20:]

                    # Decompress content
                    decompress_content = zlib.decompress(content)

                    data_length = len(zlib.compress(decompress_content))

                    total_length = length_bytes + data_length + 20
                    unread_data = unread_data[total_length:]

                    # Get parent object
                    for object in objects:
                        if object.hash() == name_base_object:
                            print(object.hash())
                            index = objects[-1].index + objects[-1].length
                            print("Hash found")
                            objects.append(
                                object_type.create_object()(
                                    content=decompress_content,
                                    base_object=object,
                                    index=index,
                                    length=data_length,
                                )
                            )
                            break

                if object_type == ObjectType.OFS_DELTA:
                    print("OFS")

                    no_of_offset_bytes, offset = get_length(unread_data)

                    base_object_index = objects[-1].index + objects[-1].length - offset

                    content = content[no_of_offset_bytes:]
                    # Decompress content
                    decompress_content = zlib.decompress(content)

                    data_length = len(zlib.compress(decompress_content))
                    total_length = length_bytes + data_length + no_of_offset_bytes
                    # print(length_bytes, data_length)
                    for object in objects:
                        if object.index == base_object_index:
                            objects.append(
                                object_type.create_object()(
                                    content=decompress_content,
                                    base_object=object,
                                    index=objects[-1].index + objects[-1].length,
                                    length=data_length,
                                )
                            )

                    unread_data = unread_data[total_length:]
                    pass

            pass
    print("All objects", len(objects), [object.object_type for object in objects])

    return objects
