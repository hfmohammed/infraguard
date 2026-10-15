"""InfraGuard command-line interface."""

from __future__ import annotations

import typer

from infraguard import __version__

app = typer.Typer(help="Validate Kubernetes and Terraform infrastructure safely.", no_args_is_help=True)


def version_callback(value: bool) -> None:
    """Print package version and stop."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", callback=version_callback, is_eager=True),
) -> None:
    """Run InfraGuard."""


def main() -> None:
    """Console-script entry point."""
    app()

