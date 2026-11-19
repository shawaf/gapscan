import os
import zipfile

DEST = os.path.realpath("/srv/uploads")


def unpack(path: str) -> None:
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            target = os.path.realpath(os.path.join(DEST, name))
            if not target.startswith(DEST + os.sep):
                raise ValueError("unsafe archive member")
            zf.extract(name, DEST)
