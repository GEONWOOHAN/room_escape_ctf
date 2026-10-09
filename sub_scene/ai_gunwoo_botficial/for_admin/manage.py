import argparse
import sqlite3
from pathlib import Path


def reset_team(database: Path, team: str) -> bool:
    with sqlite3.connect(database) as conn:
        conn.execute("BEGIN IMMEDIATE")
        exists = conn.execute("SELECT 1 FROM teams WHERE team_id=?", (team,)).fetchone()
        if not exists:
            conn.rollback()
            return False
        conn.execute("DELETE FROM comments WHERE team_id=?", (team,))
        conn.execute("DELETE FROM teams WHERE team_id=?", (team,))
        conn.commit()
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="봇피셜 운영 상태 관리")
    parser.add_argument("--db", type=Path, default=Path("/data/botficial.db"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    reset = subparsers.add_parser("reset-team", help="reset one team's feed and budget")
    reset.add_argument("team")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"database not found: {args.db}")
    if args.command == "reset-team":
        if not reset_team(args.db, args.team):
            parser.error(f"unknown team: {args.team}")
        print(f"reset team: {args.team}")


if __name__ == "__main__":
    main()
