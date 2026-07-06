from pathlib import Path

import yaml

from detectionforge.models.scenario import Scenario


def load_scenario(path: str | Path) -> Scenario:
    scenario_path = Path(path)

    with scenario_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return Scenario.model_validate(data)


if __name__ == "__main__":
    scenario = load_scenario("scenarios/suspicious_powershell.yaml")
    print(scenario.model_dump())
