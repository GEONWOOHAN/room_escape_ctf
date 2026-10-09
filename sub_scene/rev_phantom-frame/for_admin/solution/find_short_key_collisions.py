#!/usr/bin/env python3

from model_virtual_slots import short_key


def padding_for_frame(target_frame: int) -> int:
    # selected family gets frame 2; padding callees start at frame 3; the
    # cap-check wrapper is allocated after all padding call sites.
    return target_frame - 3


def main() -> None:
    user_key = short_key(1, 1, 13)
    answers = []
    for frame in range(2, 65):
        if short_key(2, frame, 13) == user_key:
            answers.append((frame, padding_for_frame(frame)))
    print("frame/padding solutions:", answers)
    assert answers[:3] == [(17, 14), (33, 30), (49, 46)]


if __name__ == "__main__":
    main()
