import argparse
import csv
import hashlib
import secrets
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="봇피셜 팀 토큰 생성")
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--tokens", type=Path, default=Path("team_tokens.txt"))
    parser.add_argument("--roster", type=Path, default=Path("team_tokens.csv"))
    parser.add_argument("--force", action="store_true", help="overwrite existing output files")
    args = parser.parse_args()
    if not 1 <= args.count <= 200:
        parser.error("count must be between 1 and 200")
    existing = [path for path in (args.tokens, args.roster) if path.exists()]
    if existing and not args.force:
        parser.error(
            "refusing to overwrite existing token files: "
            + ", ".join(str(path) for path in existing)
            + " (use --force only before the event)"
        )
    tokens = []
    roster = []
    for number in range(1, args.count + 1):
        team = f"team-{number:02d}"
        token = "ctfd_" + secrets.token_urlsafe(24)
        token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        tokens.append(f"sha256${token_digest}:{team}")
        roster.append((team, token))

    args.tokens.write_text("\n".join(tokens) + "\n", encoding="utf-8")
    with args.roster.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow(("team_id", "team_token"))
        writer.writerows(roster)
    print(f"generated {args.count} team tokens: {args.tokens} / {args.roster}")


if __name__ == "__main__":
    main()
