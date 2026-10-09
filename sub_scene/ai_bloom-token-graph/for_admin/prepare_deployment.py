from __future__ import annotations

import argparse
import csv
import io
import os
import secrets
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
SCOREBOARD_FLAG = "SHA{bl00m_0r4cl3_tr4c3s_t0k3n_gr4phs}"
DEFAULT_SECRET_DIR = (
    Path.home() / ".local" / "share" / "wargame-deployments" / "bloom-token-graph"
)


def write_private(path: Path, content: str) -> None:
    if path.exists():
        os.chmod(path, 0o600)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
    os.chmod(path, 0o600)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError(f"비밀 파일 권한을 0600으로 설정하지 못했습니다: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bloom Token Graph 운영용 플래그와 팀 토큰을 생성합니다."
    )
    parser.add_argument("--teams", type=int, default=90)
    parser.add_argument(
        "--bind-address", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1"
    )
    parser.add_argument("--port", type=int, default=40542)
    parser.add_argument("--secret-dir", type=Path, default=DEFAULT_SECRET_DIR)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if not 1 <= args.teams <= 128:
        parser.error("--teams는 1 이상 128 이하여야 합니다.")
    if not 1 <= args.port <= 65535:
        parser.error("--port는 1 이상 65535 이하여야 합니다.")

    secret_dir = args.secret_dir.expanduser().resolve()
    deployment_env_path = secret_dir / "deployment.env"
    token_path = secret_dir / "team_tokens.csv"
    existing = [path.name for path in (deployment_env_path, token_path) if path.exists()]
    if existing and not args.force:
        parser.error(f"이미 존재합니다: {', '.join(existing)} (--force로 재생성)")

    secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(secret_dir, 0o700)
    if stat.S_IMODE(secret_dir.stat().st_mode) != 0o700:
        raise RuntimeError(f"비밀 디렉터리를 0700으로 설정하지 못했습니다: {secret_dir}")

    rows = [
        (f"team-{number:03d}", secrets.token_hex(24))
        for number in range(1, args.teams + 1)
    ]
    deployment_env = "\n".join(
        (
            f"TEAM_TOKENS={','.join(token for _, token in rows)}",
            f"SCOREBOARD_FLAG={SCOREBOARD_FLAG}",
            f"SESSION_SECRET={secrets.token_hex(32)}",
            f"DEPLOYMENT_ID={secrets.token_hex(16)}",
            "",
        )
    )
    token_csv = io.StringIO()
    writer = csv.writer(token_csv, lineterminator="\n")
    writer.writerow(("team_id", "team_token"))
    writer.writerows(rows)

    write_private(deployment_env_path, deployment_env)
    write_private(token_path, token_csv.getvalue())

    ENV_PATH.write_text(
        "\n".join(
            (
                f"BLOOM_ENV_FILE={deployment_env_path}",
                f"BLOOM_BIND_ADDRESS={args.bind_address}",
                f"BLOOM_PORT={args.port}",
                f"BLOOM_EXAMPLE_TEAM_TOKEN={rows[0][1]}",
                "",
            )
        ),
        encoding="utf-8",
    )
    print(f"생성 완료: {secret_dir} ({args.teams}팀)")
    print("비밀값은 출력하지 않았습니다. 디렉터리는 0700, 파일은 0600입니다.")


if __name__ == "__main__":
    main()
