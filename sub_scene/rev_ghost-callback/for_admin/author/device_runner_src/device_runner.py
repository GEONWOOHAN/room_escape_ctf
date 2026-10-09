#!/usr/bin/env python3
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "vendor"))
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_INTR, UC_HOOK_MEM_READ)
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

FLASH = 0x08000000
SRAM = 0x20000000
MMIO = 0x40001000
NVIC_PAGE = 0xE000E000
CALIBRATION = SRAM + 0x1000
CONTEXT = SRAM + 0x2000
CALLBACK_COUNT = 96
EXPECTED_TRANSCRIPT = 160


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_small(path, maximum):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "파일 크기 제한 초과")
    return data


def calibration(data):
    require(len(data) == 64 and data[:4] == b"CAL1", "보정 파일 형식 오류")
    require(zlib.crc32(data[:56]) & 0xFFFFFFFF == struct.unpack_from("<I", data, 56)[0], "보정 CRC 오류")
    require(data[60:64] == bytes(4), "보정 예약 필드 오류")
    return struct.unpack_from("<I", data, 4)[0], data[8:24], data[24:40], data[40:56]


def read_events(path):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "중복 JSON 필드")
            result[key] = value
        return result
    document = json.loads(read_small(path, 262144), object_pairs_hook=no_duplicates)
    require(type(document) is dict and set(document) == {"events"}, "이벤트 문서 형식 오류")
    events = document["events"]
    require(type(events) is list and len(events) <= 512, "이벤트 수 제한 초과")
    previous = -1
    for event in events:
        require(type(event) is dict and set(event) == {"cycle", "channel", "sample", "status"}, "이벤트 필드 오류")
        require(all(type(value) is int for value in event.values()), "이벤트 값은 정수여야 함")
        require(previous < event["cycle"] <= 1000000, "cycle 순서 또는 범위 오류")
        require(0 <= event["channel"] < CALLBACK_COUNT and 0 <= event["sample"] <= 255, "센서 값 범위 오류")
        require(event["status"] in (0, 1), "정의되지 않은 상태 비트")
        previous = event["cycle"]
    return events


def run_firmware(firmware, calibration_data, events):
    require(len(firmware) == 65536, "펌웨어 크기 오류")
    calibration(calibration_data)
    emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emulator.mem_map(FLASH, 0x10000)
    emulator.mem_map(SRAM, 0x10000)
    emulator.mem_map(MMIO, 0x1000)
    emulator.mem_map(NVIC_PAGE, 0x2000)
    emulator.mem_write(FLASH, firmware)
    emulator.mem_write(CALIBRATION, calibration_data)
    stack, reset = struct.unpack_from("<II", firmware, 0)
    isr = struct.unpack_from("<I", firmware, 16 * 4)[0]
    require(SRAM <= stack < SRAM + 0x10000 and FLASH <= (reset & ~1) < FLASH + len(firmware), "벡터 테이블 오류")
    emulator.reg_write(UC_ARM_REG_SP, stack)
    state = {"instructions": 0, "event": 0, "pending": False, "clear_status": False}
    final_cycle = events[-1]["cycle"] if events else 0

    def code_hook(uc, address, size, _):
        state["instructions"] += 1
        if state["clear_status"]:
            uc.mem_write(MMIO, struct.pack("<I", 0))
            state["pending"] = False
            state["clear_status"] = False
        if not state["pending"] and state["event"] < len(events):
            event = events[state["event"]]
            if state["instructions"] >= event["cycle"]:
                uc.mem_write(MMIO + 4, struct.pack("<I", event["sample"]))
                uc.mem_write(MMIO + 8, struct.pack("<I", event["channel"]))
                uc.mem_write(MMIO, struct.pack("<I", event["status"]))
                state["pending"] = bool(event["status"])
                state["event"] += 1
        if state["event"] == len(events) and not state["pending"] and state["instructions"] > final_cycle + 2000:
            uc.emu_stop()

    def status_read_hook(uc, access, address, size, value, _):
        if address == MMIO and struct.unpack("<I", bytes(uc.mem_read(MMIO, 4)))[0] & 1:
            state["clear_status"] = True

    def interrupt_hook(uc, interrupt_number, _):
        # SVC는 비동기 센서 IRQ가 대기 중임을 runner에 알리는 트랩이다.
        return_pc = uc.reg_read(UC_ARM_REG_PC)
        uc.reg_write(UC_ARM_REG_LR, return_pc | 1)
        uc.reg_write(UC_ARM_REG_PC, isr)

    emulator.hook_add(UC_HOOK_CODE, code_hook)
    emulator.hook_add(UC_HOOK_MEM_READ, status_read_hook, begin=MMIO, end=MMIO)
    emulator.hook_add(UC_HOOK_INTR, interrupt_hook)
    maximum = max(final_cycle + 10000, 20000)
    emulator.emu_start(reset, FLASH + len(firmware), count=maximum)
    length = struct.unpack("<I", bytes(emulator.mem_read(CONTEXT + 4, 4)))[0]
    require(length <= EXPECTED_TRANSCRIPT and length % 8 == 0, "콜백 출력 길이 오류")
    output = bytes(emulator.mem_read(CONTEXT + 24, length))
    return output


def main():
    output_path = ROOT / "callback_outputs.bin"
    output_path.unlink(missing_ok=True)
    print("[1/4] 업데이트 검증", flush=True)
    result = subprocess.run([str(ROOT / "updater")], cwd=ROOT, capture_output=True, text=True)
    require(result.returncode == 0, result.stderr.strip() or "업데이트 실패")
    print("[2/4] 장치 파일 로드", flush=True)
    cal = read_small(ROOT / ".stage/profiles/calibration.bin", 64)
    outputs = bytearray(b"GCO5")
    print("[3/4] 세 ARM 펌웨어 순차 실행", flush=True)
    total = 0
    for name in ("a", "b", "c"):
        firmware = read_small(ROOT / f".stage/firmware/firmware_{name}.bin", 65536)
        events = read_events(ROOT / f"events_{name}.json")
        output = run_firmware(firmware, cal, events)
        outputs += struct.pack("<H", len(output)) + output
        total += len(output)
        print(f"      device_{name}: events={len(events)}, output={len(output)}", flush=True)
    output_path.write_bytes(outputs)
    print(f"[4/4] callback_outputs.bin 저장 · transcript {total}바이트", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError, UcError) as error:
        print(f"장치 실행 실패: {error}", file=sys.stderr)
        sys.exit(1)
