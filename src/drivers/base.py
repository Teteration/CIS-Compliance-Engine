from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class AuditDriver(ABC):
    """
    Abstract Base Class that all Compliance Drivers must implement.
    This ensures consistency whether scanning Oracle, Linux, or Docker.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def connect(self):
        """Establish connection to the target system."""
        pass

    @abstractmethod
    def disconnect(self):
        """Close all connections."""
        pass

    @abstractmethod
    def execute_check(self, check_type: str, command: str) -> Dict[str, Any]:
        """
        Executes a specific check command.
        
        Args:
            check_type: 'sql', 'shell', 'api', etc.
            command: The actual command string to run.
            
        Returns:
            Dict containing {'status': 'PASS'|'FAIL'|'ERROR', 'output': str}
        """
        pass