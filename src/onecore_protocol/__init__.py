"""OneCore protocol foundation. Not a network or security implementation."""
from .model import Command, Decision, evaluate_command

__all__ = ["Command", "Decision", "evaluate_command"]
