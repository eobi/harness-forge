"""hforge_mcp — a tool surface over the engine, for a model to drive.

Imports `hforge`. Is never imported by it. That direction is the whole architecture: the
arbiter was built before the model arrived, which is exactly why it can be trusted to judge
one.
"""
__all__ = ["safety", "server", "rings"]
