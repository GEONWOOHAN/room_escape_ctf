from __future__ import annotations

import hashlib
import secrets

from redis.asyncio import Redis


class StateStore:
    def __init__(self, redis: Redis, budget: int, deployment_id: str):
        if budget < 1:
            raise ValueError("request budget must be positive")
        if not deployment_id:
            raise ValueError("deployment id must not be empty")
        self.redis = redis
        self.budget = budget
        self.namespace = hashlib.sha256(deployment_id.encode()).hexdigest()[:24]

    def _key(self, team_token: str) -> str:
        digest = hashlib.sha256(team_token.encode()).hexdigest()
        return f"vault:{self.namespace}:team:{digest}"

    def _session_key(self, session: str) -> str:
        digest = hashlib.sha256(session.encode()).hexdigest()
        return f"vault:{self.namespace}:session:{digest}"

    async def create_session(self, team_token: str) -> str:
        session = secrets.token_urlsafe(32)
        await self.redis.set(self._session_key(session), team_token, ex=12 * 60 * 60)
        return session

    async def resolve_session(self, session: str) -> str | None:
        if not session:
            return None
        value = await self.redis.get(self._session_key(session))
        if value is None:
            return None
        await self.redis.expire(self._session_key(session), 12 * 60 * 60)
        return value.decode() if isinstance(value, bytes) else str(value)

    async def status(self, team_token: str) -> dict[str, int]:
        key = self._key(team_token)
        await self.redis.hsetnx(key, "counter", 0)
        counter = int(await self.redis.hget(key, "counter") or 0)
        return {"counter": counter, "remaining": max(0, self.budget - counter)}

    async def set_note(self, team_token: str, note: str) -> None:
        key = self._key(team_token)
        await self.redis.hsetnx(key, "counter", 0)
        await self.redis.hset(key, "note", note)

    async def reset_note(self, team_token: str) -> None:
        await self.redis.hset(self._key(team_token), "note", "")

    async def consume(self, team_token: str) -> tuple[int, str, int]:
        script = """
        local counter = tonumber(redis.call('HGET', KEYS[1], 'counter') or '0')
        if counter >= tonumber(ARGV[1]) then return {-1, '', 0} end
        local note = redis.call('HGET', KEYS[1], 'note') or ''
        redis.call('HSET', KEYS[1], 'counter', counter + 1)
        return {counter, note, tonumber(ARGV[1]) - counter - 1}
        """
        result = await self.redis.eval(script, 1, self._key(team_token), self.budget)
        counter = int(result[0])
        note = result[1].decode() if isinstance(result[1], bytes) else str(result[1])
        return counter, note, int(result[2])

    async def consume_many(self, team_token: str, count: int, note: str) -> tuple[int, str, int]:
        if not 1 <= count <= 256:
            raise ValueError("batch size must be between 1 and 256")
        script = """
        local counter = tonumber(redis.call('HGET', KEYS[1], 'counter') or '0')
        local count = tonumber(ARGV[2])
        if counter + count > tonumber(ARGV[1]) then return {-1, '', 0} end
        local note = ARGV[3]
        redis.call('HSET', KEYS[1], 'note', note, 'counter', counter + count)
        return {counter, note, tonumber(ARGV[1]) - counter - count}
        """
        result = await self.redis.eval(
            script, 1, self._key(team_token), self.budget, count, note
        )
        counter = int(result[0])
        note = result[1].decode() if isinstance(result[1], bytes) else str(result[1])
        return counter, note, int(result[2])
