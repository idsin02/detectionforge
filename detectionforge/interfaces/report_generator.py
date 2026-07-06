from abc import ABC, abstractmethod

from detectionforge.models.result import ForgeResult


class ReportGenerator(ABC):
    """Base class for report generation plugins."""

    @abstractmethod
    def generate(self, result: ForgeResult) -> str:
        """Generate a report."""
        raise NotImplementedError
