import os
import sys
import zlib

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


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.

    # Uncomment this block to pass the first stage

    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        if sys.argv[2] == "-p":
            print(cat_file(sys.argv[3]), end="")
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
