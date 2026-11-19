import pickle
from pathlib import Path

CACHE = Path("/var/lib/app/model.cache")  # written only by this service during startup


def load_model():
    with CACHE.open("rb") as fh:
        return pickle.load(fh)
