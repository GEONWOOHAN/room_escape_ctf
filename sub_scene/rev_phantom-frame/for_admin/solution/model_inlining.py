#!/usr/bin/env python3

from parse_profiles import parse, USER


def main() -> None:
    expected = {"alpha": 17, "beta": 33, "gamma": 49}
    for name, guard_frame in expected.items():
        profile = parse(USER / "profiles" / f"{name}.pgo")
        required_calls = guard_frame - 1
        assert int(profile["inline_budget"]) >= required_calls
        print(
            f"{name}: guard-frame={guard_frame}, inlined-calls={required_calls}, "
            f"budget={profile['inline_budget']}"
        )


if __name__ == "__main__":
    main()
