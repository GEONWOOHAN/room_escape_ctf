#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace pf {

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;

Bytes read_file(const std::filesystem::path &path, std::size_t limit = 1u << 24);
void write_file(const std::filesystem::path &path, std::span<const std::uint8_t> data);
Digest sha256(std::span<const std::uint8_t> data);
Bytes hkdf_sha256(std::span<const std::uint8_t> ikm,
                  std::span<const std::uint8_t> salt,
                  std::string_view info,
                  std::size_t output_size);
Digest blake3_small(std::span<const std::uint8_t> data);
Bytes xchacha20poly1305_encrypt(std::span<const std::uint8_t> plaintext,
                                std::span<const std::uint8_t> key,
                                std::span<const std::uint8_t> nonce,
                                std::span<const std::uint8_t> aad);
std::optional<Bytes> xchacha20poly1305_decrypt(
    std::span<const std::uint8_t> ciphertext_and_tag,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad);

std::uint16_t get_u16(std::span<const std::uint8_t> b, std::size_t off);
std::uint32_t get_u32(std::span<const std::uint8_t> b, std::size_t off);
std::uint64_t get_u64(std::span<const std::uint8_t> b, std::size_t off);
void put_u16(Bytes &b, std::uint16_t v);
void put_u32(Bytes &b, std::uint32_t v);
void put_u64(Bytes &b, std::uint64_t v);
void append(Bytes &out, std::span<const std::uint8_t> in);

enum class Op : std::uint8_t {
  Nop,
  PushI8,
  PushI32,
  PushI47,
  PushConst,
  PushNull,
  Load,
  Store,
  Dup,
  Swap,
  Pop,
  Add,
  Sub,
  Xor,
  Rol,
  Eq,
  Lt,
  NewObj,
  GetField,
  SetField,
  ShapeGuard,
  NewArray,
  GetElem,
  SetElem,
  LengthGuard,
  Jump,
  JumpZero,
  Call,
  Ret,
  TryBegin,
  TryEnd,
  Throw,
  Catch,
  FinallyEnd,
  LoopHint,
  Osr,
  DeoptHint,
  CapPublic,
  CapDerive,
  CapCheck,
  VaultSeal,
  TriggerOverflow,
  TriggerShape,
  TriggerBounds,
  Trace,
  Halt,
};

struct Instr {
  Op op{};
  std::uint32_t offset{};
  std::uint8_t size{};
  std::int64_t imm{};
  std::uint16_t a{};
  std::uint16_t b{};
  std::int32_t target{-1};
};

struct Constant {
  std::uint8_t type{};
  Bytes data;
};

struct Function {
  std::uint8_t arity{};
  std::uint8_t locals{};
  std::uint8_t max_stack{};
  std::uint8_t flags{};
  std::vector<Instr> code;
};

struct Program {
  std::uint16_t entry{};
  std::uint32_t instruction_count{};
  std::vector<Constant> constants;
  std::vector<Function> functions;
  Digest file_digest{};
};

struct ParseError {
  std::string message;
};

std::optional<Program> parse_program(std::span<const std::uint8_t> file,
                                     ParseError &error);
Digest structural_hash(const Program &program, std::size_t function_index);
Digest program_structural_hash(const Program &program);
Digest profile_selector(const Digest &function_shape, std::uint64_t layout_seed);
std::string op_label(Op op);

enum class ValueTag : std::uint8_t {
  Integer = 0,
  Object = 1,
  Function = 2,
  Capability = 3,
  Null = 4,
  String = 5,
  Array = 6,
  Boolean = 7,
};

struct Value {
  std::uint64_t raw{4};

  static Value integer(std::int64_t n);
  static Value object(std::uint32_t id);
  static Value capability(std::uint32_t id);
  static Value string(std::uint32_t id);
  static Value array(std::uint32_t id);
  static Value boolean(bool value);
  static Value null();

  ValueTag tag() const;
  std::int64_t as_integer() const;
  std::uint32_t index() const;
  bool truthy() const;
};

struct Capability {
  std::uint64_t lineage{};
  std::uint64_t parent_lineage{};
  std::uint32_t rights{};
  std::uint32_t generation{};
  std::uint32_t use_count{};
  std::uint32_t reserved{};
  std::array<std::uint8_t, 32> seal_state{};
};

struct Snapshot {
  std::uint64_t instance_seed{};
  std::uint32_t live_generation{};
  std::array<std::uint32_t, 4> shape_history{};
  std::vector<Capability> capabilities;
};

enum class Reason : std::uint8_t { Overflow = 1, Shape = 2, Bounds = 3 };
enum class LocationKind : std::uint8_t { Register = 1, Spill = 2, Constant = 3 };

struct Profile {
  std::uint8_t profile_class{};
  Reason reason{Reason::Overflow};
  LocationKind allocation{LocationKind::Register};
  std::uint8_t osr_threshold{};
  std::uint16_t inline_budget{};
  std::uint16_t warmup_count{};
  std::uint32_t predicted_shape{};
  Digest target_shape{};
  std::uint64_t layout_seed{};
};

std::optional<Snapshot> parse_snapshot(std::span<const std::uint8_t> file);
std::optional<Profile> parse_profile(std::span<const std::uint8_t> file);
Bytes capability_bytes(const Capability &cap);

struct SemanticRecord {
  std::uint8_t profile_class{};
  std::uint16_t loop_class{};
  std::array<std::uint8_t, 16> call_shape{};
  std::uint8_t source_namespace{};
  std::uint8_t restored_namespace{};
  std::uint8_t frame_relation{};
  Reason reason{Reason::Overflow};
  std::uint8_t before_type{};
  std::uint8_t after_type{};
  std::uint8_t lineage_transition{};
  std::array<std::uint8_t, 16> sink_effect{};
};
std::unordered_map<std::string, std::string>
read_config(const std::filesystem::path &path);

constexpr std::string_view kSealMessage = "archive:afterimage:open";

} // namespace pf
