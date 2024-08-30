import hashlib
import os
import re
import sys
import zlib
from binascii import unhexlify
from pathlib import Path
from typing import Dict, List, Optional

from clone.main import clone

OBJECTS_DIR = ".git/objects"


def init():
    os.mkdir(".git")
    os.mkdir(OBJECTS_DIR)
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    print("Initialized git directory")


def cat_file(file_hash: str) -> str:
    # get the first two characters of the hash
    # navigate to .git/objects/two_char/remaining hash
    with open(os.path.join(OBJECTS_DIR, file_hash[:2], file_hash[2:]), "rb") as file:
        decompressed_content = zlib.decompress(file.read()).decode()
        content = decompressed_content.split("\0", maxsplit=1)[1]
        return content
    # read the file
    # decompress the file
    # split using \0, null byte
    # return output


def ls_tree(tree_hash: str, names_only=True) -> Dict[str, List[str]]:
    if not names_only:
        raise NotImplementedError

    with open(os.path.join(OBJECTS_DIR, tree_hash[:2], tree_hash[2:]), "rb") as file:
        decompressed_content = zlib.decompress(file.read())
        content = decompressed_content.split(b"\x00", maxsplit=1)[1]

    # digit, space, (name), \0
    names = re.findall(rb"\d+ ([\d\w]+)\x00", content)

    return {"names": [name.decode() for name in names]}


def hash_object_blob(filepath: str, save=False):
    with open(filepath, "rb") as file:
        content = file.read().decode()

        size = len(content)

        data = f"blob {size}\0{content}".encode("utf-8")

        sha_hash = hashlib.sha1(data).hexdigest()

        compressed_content = zlib.compress(data)

    if save:
        file_objects_dir = os.path.join(OBJECTS_DIR, sha_hash[:2])
        os.mkdir(file_objects_dir)
        with open(os.path.join(file_objects_dir, sha_hash[2:]), "+wb") as object_file:
            object_file.write(compressed_content)

    return sha_hash


class BaseObject:
    def hash(self):
        data = self.content()

        sha_hash = hashlib.sha1(data).hexdigest()

        return sha_hash

    def write(self):
        sha_hash = self.hash()
        compressed_content = zlib.compress(self.content())

        file_objects_dir = os.path.join(OBJECTS_DIR, sha_hash[:2])
        os.mkdir(file_objects_dir)
        with open(os.path.join(file_objects_dir, sha_hash[2:]), "+wb") as object_file:
            object_file.write(compressed_content)

        return sha_hash

    def content(self):
        raise NotImplementedError


class Object(BaseObject):
    def __init__(self, path: str):
        self.path = path

    def mode(self):
        raise NotImplementedError


class Blob(Object):

    def content(self):
        with open(self.path, "rb") as file:
            content = file.read().decode()

            size = len(content)

            data = f"blob {size}\0{content}".encode("utf-8")

            return data

    def mode(self):
        return "100644"


class Tree(Object):

    def get_object_from_path(self, path) -> Object:
        if Path(path).is_dir():
            return Tree(path)
        else:
            return Blob(path)

    def content(self):
        entries = []

        for path in sorted(os.listdir(self.path)):
            entry_path = os.path.join(self.path, path)

            if ".git" in str(entry_path):
                continue

            object = self.get_object_from_path(entry_path)

            data = (
                f"{object.mode()} {os.path.basename(object.path)}\0".encode()
                + bytes.fromhex(object.hash())
            )

            entries.append(data)

        entries_str = b"".join(entries)
        size = len(entries_str)

        content = f"tree {size}\0".encode() + entries_str
        return content

    def mode(self):
        return "40000"


class CommitTree(Object):
    def __init__(
        self, tree_sha: str, parent_sha: Optional[str] = None, commit_message: str = ""
    ):
        self._tree_sha = tree_sha
        self._parent_sha = parent_sha
        self._commit_message = commit_message

    def content(self):
        author_name = "Josh596"
        email = "randomemail@users.noreply.githubcom"
        timestamp = "1723506942"
        timezone = "+0100"

        tree = f"tree {self._tree_sha}"
        parent = f"parent {self._parent_sha}" if self._parent_sha else ""
        author = f"{author_name} <{email}> {timestamp} {timezone}"
        commiter = f"{author_name} <{email}>  {timestamp} {timezone}\n\n{self._commit_message}\n"

        data = f"{tree}\n{parent}\n{author}\n{commiter}"
        content = f"commit {len(data)}\0{data}".encode()

        return content


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.

    # Uncomment this block to pass the first stage

    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        if sys.argv[2] == "-p":
            print(cat_file(sys.argv[3]), end="")
    elif command == "hash-object":
        if sys.argv[2] == "-w":
            print(hash_object_blob(sys.argv[3], save=True), end="")
        else:
            print(hash_object_blob(sys.argv[3]), end="")
    elif command == "ls-tree":
        if sys.argv[2] == "--name-only":
            print(*ls_tree(sys.argv[3])["names"], sep="\n")
    elif command == "write-tree":
        print(Tree("./").write())

    elif command == "commit-tree":
        tree_sha = sys.argv[2]
        parent_sha = sys.argv[4]
        commit_message = sys.argv[6]
        print(CommitTree(tree_sha, parent_sha, commit_message).write())
    elif command == "clone":
        TEST_GIT_URL = "https://github.com/Josh596/Weather-App.git"
        clone(TEST_GIT_URL, "/Users/Josh/Desktop/Personal-Projects/git_test")
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
