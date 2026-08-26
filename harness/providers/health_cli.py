from pathlib import Path
import json
import typer

from harness.providers.config import load_provider_configs
from harness.providers.registry import check_provider_health

app = typer.Typer(no_args_is_help=True)


@app.command()
def health(
    config: Path = typer.Option(..., "--config"),
):
    results = []

    for provider_config in load_provider_configs(config):
        health_result = check_provider_health(provider_config)
        results.append(health_result.__dict__)

    typer.echo(json.dumps(results, indent=2))


if __name__ == "__main__":
    app()