from pathlib import Path
from typing import Protocol

from harness.models.finding import Finding

class ReconParser(Protocol):
    tool_name: str

    def can_parse(self, path: Path, content: str) -> bool:
        ...
    
    def parse(self, path: Path, content: str) -> list[Finding]:
        ...