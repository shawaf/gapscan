import json

CONFIG_PATH = "/etc/myapp/settings.json"


def load_settings():
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        return json.load(fh)
