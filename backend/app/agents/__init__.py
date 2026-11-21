"""Workflow-stage agents. Each agent is a function that calls registered tools,
persists evidence, and records a structured decision. The LLM provider is used
ONLY to phrase reasoning summaries over tool-derived facts."""
