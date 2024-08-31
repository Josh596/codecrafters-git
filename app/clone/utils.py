import os

from .constants import OBJECTS_DIR


def init(parent_dir):
    os.chdir(parent_dir)
    if os.path.exists(".git"):
        raise Exception("Directory is already a git repository")
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


def get_bit(byte: int, position: int):
    return (byte >> (7 - position)) & 1


def get_length(data):
    length_bytes = []

    for byte_ in data:
        mask = 0b1111111
        length_bytes.append(format(byte_ & mask, "07b"))
        if byte_ < 128:  # so MSB is not set
            break
    length_bytes_reversed = list(reversed(length_bytes))
    length_bits = "".join(length_bytes_reversed)
    length_object = int(length_bits, 2)
    print(length_bits)
    return len(length_bytes), length_object


# 1001
# 00010000110
