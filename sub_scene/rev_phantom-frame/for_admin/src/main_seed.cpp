#include "engine.hpp"

#include <array>
#include <fstream>
#include <iostream>

namespace {

std::uint64_t digest_u64(std::string_view label, std::uint64_t seed) {
  pf::Bytes material(label.begin(), label.end());
  pf::put_u64(material, seed);
  const auto digest = pf::sha256(material);
  return pf::get_u64(digest, 0);
}

std::array<std::uint8_t, 32> digest_bytes(std::string_view label,
                                          std::uint64_t seed) {
  pf::Bytes material(label.begin(), label.end());
  pf::put_u64(material, seed);
  return pf::sha256(material);
}

std::uint32_t shape_value(std::uint64_t seed, std::uint8_t index) {
  const auto value = digest_u64("shape-history", seed ^ index);
  return static_cast<std::uint32_t>(4 + value % 211);
}

pf::Bytes make_snapshot(std::uint64_t seed) {
  const auto generation =
      static_cast<std::uint32_t>(0x1000u + digest_u64("generation", seed) % 0xefffu);
  const auto public_lineage = digest_u64("public-lineage", seed) | 1;
  const auto audit_lineage = digest_u64("audit-lineage", seed) | 1;
  const auto root_lineage = digest_u64("root-lineage", seed) | 1;
  std::array<pf::Capability, 3> caps{};
  caps[0] = {public_lineage, 0, 0x00000001u, generation, 0, 0,
             digest_bytes("public-seal", seed)};
  caps[1] = {audit_lineage, public_lineage, 0x00000007u, generation, 0, 0,
             digest_bytes("audit-seal", seed)};
  caps[2] = {root_lineage, audit_lineage, 0x80000007u, generation, 0, 0,
             digest_bytes("root-seal", seed)};
  pf::Bytes out{'P', 'S', 'N', 'P'};
  pf::put_u16(out, 1);
  pf::put_u16(out, caps.size());
  pf::put_u64(out, seed);
  pf::put_u32(out, generation);
  for (std::uint8_t i = 0; i < 4; ++i)
    pf::put_u32(out, shape_value(seed, i));
  pf::put_u32(out, 0);
  for (const auto &cap : caps)
    pf::append(out, pf::capability_bytes(cap));
  const auto checksum = pf::sha256(out);
  pf::append(out, checksum);
  return out;
}

pf::Bytes make_profile(std::uint8_t profile_class, pf::Reason reason,
                       pf::LocationKind allocation, std::uint8_t threshold,
                       std::uint16_t inline_budget, std::uint16_t warmup,
                       std::uint32_t predicted_shape,
                       const pf::Digest &target_shape,
                       std::uint64_t layout_seed) {
  pf::Bytes out{'P', 'P', 'G', 'O'};
  pf::put_u16(out, 1);
  out.push_back(profile_class);
  out.push_back(static_cast<std::uint8_t>(reason));
  out.push_back(static_cast<std::uint8_t>(allocation));
  out.push_back(threshold);
  pf::put_u16(out, inline_budget);
  pf::put_u16(out, warmup);
  pf::put_u16(out, 0);
  pf::put_u32(out, predicted_shape);
  const auto selector = pf::profile_selector(target_shape, layout_seed);
  pf::append(out, selector);
  pf::put_u64(out, layout_seed);
  pf::put_u32(out, 0);
  const auto checksum = pf::sha256(out);
  pf::append(out, checksum);
  return out;
}

} // namespace

int main(int argc, char **) {
  if (argc != 1)
    return 2;
  try {
    const auto admin = pf::executable_directory().parent_path();
    const auto root = admin.parent_path();
    const auto user = root / "for_user";
    const auto solution = admin / "solution";
    pf::ParseError error;
    const auto reference = pf::parse_program(
        pf::read_file(solution / "reference_candidate.pbc", 16384),
        error);
    if (!reference || reference->functions.size() < 6)
      throw std::runtime_error("reference candidate");
    std::ifstream seed_input(admin / "instance.seed");
    std::string seed_text;
    seed_input >> seed_text;
    if (!seed_input || seed_text.empty())
      throw std::runtime_error("instance seed");
    const auto seed = std::stoull(seed_text, nullptr, 0);
    const auto snapshot = make_snapshot(seed);
    pf::write_file(user / "runtime.snap", snapshot);
    const auto alpha = make_profile(
        1, pf::Reason::Overflow, pf::LocationKind::Register, 2,
        static_cast<std::uint16_t>(18 + seed % 3),
        static_cast<std::uint16_t>(88 + seed % 17), shape_value(seed, 0),
        pf::structural_hash(*reference, 3), digest_u64("alpha-layout", seed));
    const auto beta = make_profile(
        2, pf::Reason::Shape, pf::LocationKind::Spill, 3,
        static_cast<std::uint16_t>(34 + seed % 3),
        static_cast<std::uint16_t>(120 + seed % 17), shape_value(seed, 1),
        pf::structural_hash(*reference, 4), digest_u64("beta-layout", seed));
    const auto gamma = make_profile(
        3, pf::Reason::Bounds, pf::LocationKind::Constant, 4,
        static_cast<std::uint16_t>(50 + seed % 3),
        static_cast<std::uint16_t>(184 + seed % 17), shape_value(seed, 2),
        pf::structural_hash(*reference, 5), digest_u64("gamma-layout", seed));
    pf::write_file(user / "profiles" / "alpha.pgo", alpha);
    pf::write_file(user / "profiles" / "beta.pgo", beta);
    pf::write_file(user / "profiles" / "gamma.pgo", gamma);
    std::cout << "instance data generated\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "seed generation failed: " << e.what() << '\n';
    return 1;
  }
}
