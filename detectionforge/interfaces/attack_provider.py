from abc import ABC, abstractmethod

from detectionforge.models.scenario import Scenario
from detectionforge.models.result import AttackResult


class AttackProvider(ABC):
    """Base class for attack execution plugins."""

    @abstractmethod
    def run(self, scenario: Scenario) -> AttackResult:
        """Execute the attack scenario."""
        raise NotImplementedError
