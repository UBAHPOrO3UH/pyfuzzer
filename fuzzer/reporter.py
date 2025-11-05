import json
import os
from typing import List, Dict, Any

class Reporter:
    def __init__(self, json_path: str = "outputs/results.json"):
        self.json_path = json_path
        self._items: List[Dict[str, Any]] = []
        os.makedirs(os.path.dirname(self.json_path) or ".", exist_ok=True)

    def add(self, item: Dict[str, Any]):
        self._items.append(item)

    def save(self):
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(self._items, f, ensure_ascii=False, indent=2)
