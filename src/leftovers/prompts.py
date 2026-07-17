from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True)
class RenderedPrompt:
    stage: str
    text: str
    sha256: str


def _json_for_delimited_prompt(value: Any) -> str:
    serialized = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    # Prevent source data from creating literal delimiter or HTML-like control text.
    return serialized.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def render_prompt(stage: str, task_data: dict[str, Any]) -> RenderedPrompt:
    if stage not in {"planning", "implementation", "review", "pr-writer"}:
        raise ValueError(f"unknown prompt stage: {stage}")
    prompt_root = files("leftovers").joinpath("prompt_templates")
    system = prompt_root.joinpath("system.md").read_text()
    stage_text = prompt_root.joinpath(f"{stage}.md").read_text()
    if set(task_data) != {"trusted", "untrusted"}:
        raise ValueError("task data must have exactly trusted and untrusted envelopes")
    trusted = _json_for_delimited_prompt(task_data["trusted"])
    untrusted = _json_for_delimited_prompt(task_data["untrusted"])
    text = (
        system.rstrip()
        + "\n\n"
        + stage_text.rstrip()
        + '\n\n<trusted_task_envelope encoding="json">\n'
        + trusted
        + "\n</trusted_task_envelope>\n\n"
        + '<untrusted_sources encoding="json">\n'
        + untrusted
        + "\n</untrusted_sources>\n"
    )
    return RenderedPrompt(stage=stage, text=text, sha256=hashlib.sha256(text.encode()).hexdigest())
