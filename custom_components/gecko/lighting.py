"""RGB normalization adapted from @nmonteleone18's Gecko fork."""
from __future__ import annotations


def split_brightness(rgb: tuple[int, int, int]) -> tuple[tuple[int, int, int], int]:
    """Split a reported colour into its full-brightness hue and a brightness."""
    brightness = max(rgb)
    if brightness == 0:
        return tuple(rgb), 0
    return tuple(round(c * 255 / brightness) for c in rgb), brightness


def rgbi_payload(
    rgb: tuple[int, int, int], brightness: int, intensity: float = 1
) -> list[float]:
    """Build the shadow payload for ``rgb`` dimmed to ``brightness`` (1-255)."""
    full, _ = split_brightness(rgb)
    level = max(0, min(255, int(brightness)))
    return [*(round(c * level / 255) for c in full), intensity]

