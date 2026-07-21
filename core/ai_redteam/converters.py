"""Prompt converters for local AI red-team planning.

Converters are deterministic and local. They transform synthetic probe text for
planning/evaluation only; they do not call models, tools, or targets.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List


HOMOGLYPHS = str.maketrans(
    {
        "a": "а",  # Cyrillic small a
        "e": "е",  # Cyrillic small ie
        "o": "о",  # Cyrillic small o
        "p": "р",  # Cyrillic small er
        "c": "с",  # Cyrillic small es
        "x": "х",  # Cyrillic small ha
    }
)


CONVERTERS: Dict[str, Dict[str, Any]] = {
    "identity": {
        "description": "Return the prompt unchanged.",
        "modifies_payload": False,
    },
    "base64": {
        "description": "Base64-encode the prompt for normalization tests.",
        "modifies_payload": True,
    },
    "homoglyph": {
        "description": "Replace selected ASCII characters with Unicode confusables.",
        "modifies_payload": True,
    },
    "multi_turn": {
        "description": "Represent the prompt as a three-turn interaction plan.",
        "modifies_payload": True,
    },
}


@dataclass(frozen=True)
class ConverterResult:
    """Result of applying one prompt converter."""

    converter: str
    text: str
    steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "converter": self.converter,
            "text": self.text,
            "payload_preview": self.text[:240],
            "payload_length": len(self.text),
            "steps": self.steps,
            "metadata": self.metadata,
        }


def convert_prompt(prompt: str, converter: str = "identity") -> ConverterResult:
    """Apply a named deterministic prompt converter."""
    if converter in {"identity", "direct"}:
        return ConverterResult(
            converter="identity",
            text=prompt,
            steps=["identity"],
            metadata={"modifies_payload": False},
        )
    if converter in {"base64", "encoding"}:
        transformed = base64.b64encode(prompt.encode("utf-8")).decode("ascii")
        return ConverterResult(
            converter="base64",
            text=transformed,
            steps=["base64_encode"],
            metadata={"modifies_payload": True},
        )
    if converter == "homoglyph":
        transformed = prompt.translate(HOMOGLYPHS)
        return ConverterResult(
            converter="homoglyph",
            text=transformed,
            steps=["replace_confusable_characters"],
            metadata={"modifies_payload": True},
        )
    if converter == "multi_turn":
        transformed = " || ".join(
            [
                "turn_1: establish benign task context",
                f"turn_2: introduce probe marker {prompt}",
                "turn_3: request final answer and observe boundary handling",
            ]
        )
        return ConverterResult(
            converter="multi_turn",
            text=transformed,
            steps=["split_context", "send_three_turn_plan"],
            metadata={"modifies_payload": True},
        )
    return ConverterResult(
        converter=converter,
        text=prompt,
        steps=["custom_converter_placeholder"],
        metadata={"modifies_payload": False, "unknown_converter": True},
    )


def converters_summary() -> Dict[str, Any]:
    """Return built-in converter metadata."""
    return {
        "converters": len(CONVERTERS),
        "converter_names": sorted(CONVERTERS),
        "items": CONVERTERS,
    }
