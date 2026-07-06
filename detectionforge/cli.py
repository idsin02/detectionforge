
import typer
from rich import print

from detectionforge.engine import ValidationEngine
from detectionforge.loader import load_scenario
from detectionforge.plugins.dummy.attack import DummyAttackProvider
from detectionforge.plugins.dummy.backend import DummyDetectionBackend
from detectionforge.plugins.dummy.collector import DummyTelemetryCollector

app = typer.Typer(help="DetectionForge CLI")


@app.command()
def validate(scenario: str):
    """Validate a detection scenario."""

    scenario_obj = load_scenario(scenario)

    engine = ValidationEngine(
        attack_provider=DummyAttackProvider(),
        telemetry_collector=DummyTelemetryCollector(),
        detection_backend=DummyDetectionBackend(),
    )

    result = engine.run(scenario_obj)

    print("[bold green]Validation Complete[/bold green]")
    print(result.model_dump())


if __name__ == "__main__":
    app()
