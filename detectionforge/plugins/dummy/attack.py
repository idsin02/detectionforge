from detectionforge.interfaces.attack_provider import AttackProvider
from detectionforge.models.result import AttackResult
from detectionforge.models.scenario import Scenario


class DummyAttackProvider(AttackProvider):
    def run(self, scenario: Scenario) -> AttackResult:
        return AttackResult(
            provider=scenario.attack.provider,
            status="success",
        )
