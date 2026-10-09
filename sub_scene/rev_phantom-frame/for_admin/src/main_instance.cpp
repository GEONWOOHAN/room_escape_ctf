#include "engine.hpp"

#include <algorithm>
#include <array>
#include <iostream>

int main(int argc, char **) {
  if (argc != 1)
    return 2;
  try {
    const auto admin = pf::executable_directory().parent_path();
    const auto root_dir = admin.parent_path();
    const auto user = root_dir / "for_user";
    const auto solution = admin / "solution";
    pf::ParseError error;
    const auto program = pf::parse_program(
        pf::read_file(solution / "reference_candidate.pbc", 16384),
        error);
    const auto snapshot =
        pf::parse_snapshot(pf::read_file(user / "runtime.snap", 65536));
    if (!program || !snapshot)
      throw std::runtime_error("private input");
    const auto reference =
        pf::execute(*program, *snapshot, pf::Tier::Interpreter, nullptr, false);
    if (!reference.valid || !reference.terminated || reference.sink_success)
      throw std::runtime_error("reference safety");
    std::vector<pf::SemanticRecord> records;
    std::array<pf::Digest, 3> seals{};
    const std::array<std::string, 3> names = {"alpha", "beta", "gamma"};
    for (std::size_t i = 0; i < names.size(); ++i) {
      const auto profile = pf::parse_profile(
          pf::read_file(user / "profiles" / (names[i] + ".pgo"), 4096));
      if (!profile)
        throw std::runtime_error("profile");
      for (std::uint16_t warmup = 0; warmup < profile->warmup_count; ++warmup) {
        const auto baseline = pf::execute(*program, *snapshot,
                                          pf::Tier::Baseline, nullptr, false);
        if (!baseline.valid || !baseline.terminated || baseline.sink_success)
          throw std::runtime_error("baseline warmup");
      }
      const auto result = pf::execute(*program, *snapshot, pf::Tier::Optimizing,
                                      &*profile, false);
      if (!result.valid || !result.terminated || !result.sink_success ||
          !result.security_deopt || !result.record)
        throw std::runtime_error("reference exploit");
      records.push_back(*result.record);
      seals[i] = result.seal;
    }
    const auto raw = pf::encode_transcript(records);
    const auto commitment = pf::sha256(raw);
    pf::write_file(user / "transcript.commit", commitment);

    pf::Receipt receipt;
    receipt.raw_transcript = raw;
    receipt.seals = seals;
    receipt.program_checksum = pf::program_structural_hash(*program);
    const auto encoded_receipt = pf::encode_receipt(receipt);
    pf::write_file(solution / "expected_receipt.bin",
                   encoded_receipt);
    pf::write_file(solution / "raw_expected_transcript.bin", raw);

    auto flag = pf::read_file(admin / "flag.txt", 512);
    while (!flag.empty() && (flag.back() == '\n' || flag.back() == '\r'))
      flag.pop_back();
    if (flag.size() < 7)
      throw std::runtime_error("flag");
    pf::Bytes nonce_material{'n', 'o', 'n', 'c', 'e'};
    pf::append(nonce_material, program->file_digest);
    pf::put_u64(nonce_material, snapshot->instance_seed);
    const auto nonce_digest = pf::sha256(nonce_material);
    std::array<std::uint8_t, 24> nonce{};
    std::copy_n(nonce_digest.begin(), 24, nonce.begin());
    pf::Bytes salt_material{'s', 'a', 'l', 't'};
    pf::append(salt_material, commitment);
    pf::put_u64(salt_material, snapshot->instance_seed);
    const auto salt = pf::sha256(salt_material);
    const auto key = pf::derive_flag_key(raw, seals, salt);
    const auto encrypted = pf::encode_encrypted_flag(flag, key, salt, nonce);
    pf::write_file(user / "flag.enc", encrypted);
    pf::write_file(solution / "derived_flag_key.bin", key);
    std::cout << "commitment and encrypted flag generated\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "instance finalization failed: " << e.what() << '\n';
    return 1;
  }
}
