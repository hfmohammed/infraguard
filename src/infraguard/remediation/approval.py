"""Interactive human approval boundary."""

import sys


def request_approval(resource_name: str) -> bool:
    """Require a real TTY and an exact resource-name confirmation."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("approval requires an interactive terminal")
    answer = input(f'Type the resource name "{resource_name}" to approve: ')
    return answer == resource_name
