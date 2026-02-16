from abc import ABC, abstractmethod
from typing import Any, Dict

class AuditDriver(ABC):
    """Abstract Base Class for all compliance drivers."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def connect(self):
        """Establish connection to the target."""
        pass

    @abstractmethod
    def disconnect(self):
        """Close connection."""
        pass

    @abstractmethod
    def execute(self, check: str, check_type: str) -> Dict[str, Any]:
        """
        Run a single check.
        Returns: {'status': 'PASS'|'FAIL', 'output': str}
        """
        pass