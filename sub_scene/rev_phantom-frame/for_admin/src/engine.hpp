#pragma once

#include "core.hpp"

#include <array>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pf {

enum class Tier { Interpreter, Baseline, Optimizing };

struct ExecutionResult {
  bool valid{};
  bool terminated{};
  bool sink_success{};
  bool security_deopt{};
  std::uint64_t executed_instructions{};
  std::uint32_t ir_nodes{};
  std::uint16_t inline_calls{};
  std::uint16_t deopt_count{};
  Reason deopt_reason{Reason::Overflow};
  Digest seal{};
  std::optional<SemanticRecord> record;
  std::string diagnostic;
};

ExecutionResult execute(const Program &program, const Snapshot &snapshot,
                        Tier tier, const Profile *profile, bool coarse_trace);

Bytes encode_record(const SemanticRecord &record);
std::optional<SemanticRecord> parse_record(std::span<const std::uint8_t> data);
Bytes encode_transcript(std::vector<SemanticRecord> records);
std::optional<std::vector<SemanticRecord>>
parse_transcript(std::span<const std::uint8_t> raw);
Digest compute_seal(const Capability &root, std::string_view message,
                    const SemanticRecord &record);

struct Receipt {
  Bytes raw_transcript;
  std::array<Digest, 3> seals{};
  Digest program_checksum{};
};

Bytes encode_receipt(const Receipt &receipt);
std::optional<Receipt> parse_receipt(std::span<const std::uint8_t> file);

struct EncryptedFlag {
  std::array<std::uint8_t, 32> salt{};
  std::array<std::uint8_t, 24> nonce{};
  Bytes ciphertext_and_tag;
  Bytes aad;
};

Bytes encode_encrypted_flag(std::span<const std::uint8_t> plaintext,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> salt,
                            std::span<const std::uint8_t> nonce);
std::optional<EncryptedFlag>
parse_encrypted_flag(std::span<const std::uint8_t> file);
Bytes derive_flag_key(std::span<const std::uint8_t> raw_transcript,
                      const std::array<Digest, 3> &seals,
                      std::span<const std::uint8_t> salt);

std::filesystem::path executable_directory();

} // namespace pf
