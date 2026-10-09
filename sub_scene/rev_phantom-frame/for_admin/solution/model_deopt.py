#!/usr/bin/env python3

from dataclasses import dataclass

from model_virtual_slots import full_key, short_key


@dataclass
class Node:
    full: int
    origin: str


def demonstrate(frame: int) -> None:
    buckets: dict[int, list[Node]] = {}
    shadow = Node(full_key(2, frame, 13), "root-guard")
    buckets.setdefault(short_key(2, frame, 13), []).append(shadow)
    # Cold exception states trust the bucket hit and skip full equality.
    restored = buckets[short_key(1, 1, 13)][0]
    assert restored.full != full_key(1, 1, 13)
    print(f"frame {frame}: user local materializes from {restored.origin}")


def main() -> None:
    for frame in (17, 33, 49):
        demonstrate(frame)


if __name__ == "__main__":
    main()
