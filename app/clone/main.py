"""
Step 1: Discover refs
    By sending a GET request to `C: GET $GIT_URL/info/refs?service=git-upload-pack HTTP/1.0`
Step 2: Negotiation bit, I really only need to send want requests. 
"""

import logging
import os
import re
from typing import Dict, List

from .get_packfile import discover_refs, get_pack, unpack_pack_file
from .objects import GitObject
from .utils import convert_path_to_absolute

TEST_GIT_URL = "https://github.com/Josh596/Weather-App.git"
# https://gitlab.com/beku.skrillex/jp_project


logging.basicConfig(encoding="utf-8", level=logging.INFO)


def get_objects_from_tree(content: bytes):
    data = re.findall(rb"(\d+) (.+?)\x00(.{20})", content, re.DOTALL)
    return [(mode.decode(), name.decode(), hash.hex()) for mode, name, hash in data]


def save_objects(objects: List[GitObject]):
    hash_to_object: Dict[str, GitObject] = {}

    for git_object in objects:
        hash_to_object[git_object.hash()] = git_object

    for git_object in objects:

        if git_object.object_type == "tree":
            for data in get_objects_from_tree(git_object.content):
                file_mode, name, hash = data
                obj = hash_to_object[hash]
                obj.parent = git_object
                obj.name = name

    count = 0
    for git_object in objects:

        git_object.write()
        try:
            git_object.save()
        except Exception as e:
            logging.error(
                f"Failed on count {count}.\nObject={git_object}\nObject Type={git_object.object_type}"
            )

            raise e

    count = 0
    for git_object in objects:
        count += 1
        try:
            git_object.save()
        except Exception as e:
            logging.error(
                f"Failed on count {count}.\nObject={git_object}\nObject Type={git_object.object_type}"
            )

            raise e

    # TODO: IT SHOULD ALSO STORE FILENAME OF OTHERS OHH LIKE BLOB
    # Somehow, from Tree Objects I'm supposed to reconstruct the paths, so have a dict containing the hash, and update paths appropriately


def clone(git_url: str, location: str):

    git_url = convert_path_to_absolute(git_url)
    # # Create .git folder, raise error if it already exist
    discover_refs(git_url, "git-upload-pack")
    pack_location = get_pack(git_url, location)
    # # print(pack_location, "Str")
    os.chdir(location)
    objects = unpack_pack_file(pack_location)
    save_objects(objects)

    #


if __name__ == "__main__":
    # TODO: ADD A FULL CONTENT FIELD TO GITOBJECT, CONTAINING THE FULL OBJECT[length, data, etc.] That is what I used to calculate hash
    clone(TEST_GIT_URL, "/Users/Josh/Desktop/Personal-Projects/git_test")
