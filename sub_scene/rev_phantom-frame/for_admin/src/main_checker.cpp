#include "engine.hpp"

#include <algorithm>
#include <iostream>

int main(int argc, char **) {
  if (argc != 1)
    return 2;
  try {
    const auto base = pf::executable_directory();
    pf::ParseError parse_error;
    const auto candidate_bytes = pf::read_file(base / "candidate.pbc", 16384);
    const auto program = pf::parse_program(candidate_bytes, parse_error);
    const auto snapshot =
        pf::parse_snapshot(pf::read_file(base / "runtime.snap", 65536));
    if (!program || !snapshot) {
      std::cerr << "invalid bytecode\n";
      return 1;
    }

    const auto reference =
        pf::execute(*program, *snapshot, pf::Tier::Interpreter, nullptr, false);
    if (!reference.valid || !reference.terminated || reference.sink_success ||
        reference.security_deopt) {
      std::cerr << "reference rejected\n";
      return 1;
    }

    std::vector<pf::SemanticRecord> records;
    std::array<pf::Digest, 3> seals{};
    const std::array<std::string, 3> names = {"alpha", "beta", "gamma"};
    for (std::size_t i = 0; i < names.size(); ++i) {
      const auto profile = pf::parse_profile(
          pf::read_file(base / "profiles" / (names[i] + ".pgo"), 4096));
      if (!profile)
        throw std::runtime_error("profile");
      for (std::uint16_t warmup = 0; warmup < profile->warmup_count; ++warmup) {
        const auto baseline = pf::execute(*program, *snapshot,
                                          pf::Tier::Baseline, nullptr, false);
        if (!baseline.valid || !baseline.terminated || baseline.sink_success) {
          std::cerr << "optimized rejected\n";
          return 1;
        }
      }
      const auto optimized = pf::execute(*program, *snapshot,
                                         pf::Tier::Optimizing, &*profile, false);
      if (!optimized.valid || !optimized.terminated ||
          !optimized.sink_success || !optimized.security_deopt ||
          optimized.deopt_count != 1 || !optimized.record ||
          optimized.ir_nodes > 20000 ||
          optimized.executed_instructions > 2'000'000) {
        std::cerr << "optimized rejected\n";
        return 1;
      }
      records.push_back(*optimized.record);
      seals[i] = optimized.seal;
    }

    const auto raw = pf::encode_transcript(records);
    const auto commitment = pf::read_file(base / "transcript.commit", 32);
    const auto actual = pf::sha256(raw);
    if (commitment.size() != 32 ||
        !std::equal(actual.begin(), actual.end(), commitment.begin())) {
      std::cerr << "invalid proof\n";
      return 1;
    }
    pf::Receipt receipt;
    receipt.raw_transcript = raw;
    receipt.seals = seals;
    receipt.program_checksum = pf::program_structural_hash(*program);
    const auto encoded = pf::encode_receipt(receipt);
    pf::write_file(base / "receipt.bin", encoded);
    std::cout << "proof accepted; receipt.bin created\n";
    return 0;
  } catch (...) {
    std::cerr << "invalid bytecode\n";
    return 1;
  }
}
