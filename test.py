import re

data = "040000 dir2\0abcdefghijklmnopqrst040000 dir3\0abcdefghijklmnopqrst"


names = re.findall("\d+ ([\d\w]+)\x00", data)
print(names)
