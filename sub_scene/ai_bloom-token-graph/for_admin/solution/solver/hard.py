import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from solution.solver.common import solve_http

if __name__ == "__main__":
    result = solve_http()
    print(result.flag)
    print(f"요청 수: {result.requests}")
