#!/usr/bin/env python3


def full_key(namespace: int, frame: int, slot: int) -> int:
    return ((namespace & 3) << 22) | ((frame & 0x3FF) << 12) | (slot & 0xFFF)


def short_key(namespace: int, frame: int, slot: int) -> int:
    del namespace
    return ((frame & 0xF) << 12) | (slot & 0xFFF)


def main() -> None:
    user = (1, 1, 13)
    for frame in (17, 33, 49):
        shadow = (2, frame, 13)
        assert full_key(*user) != full_key(*shadow)
        assert short_key(*user) == short_key(*shadow)
        print(f"user frame=1 / shadow frame={frame}: short=0x{short_key(*user):04x}")


if __name__ == "__main__":
    main()
