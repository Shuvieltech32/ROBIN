import json
import os

LABELS_FILE = "data/labels.json"


def load_labels():
    if not os.path.exists(LABELS_FILE):
        return {}

    with open(LABELS_FILE, "r") as f:
        try:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
        except:
            return {}
