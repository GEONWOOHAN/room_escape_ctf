#include "engine.hpp"

#include <iostream>

namespace {

std::optional<pf::Profile> load_profile(const std::filesystem::path &base,
                                        const std::string &name) {
  if (name != "alpha" && name != "beta" && name != "gamma")
    return std::nullopt;
  return pf::parse_profile(
      pf::read_file(base / "profiles" / (name + ".pgo"), 4096));
}

} // namespace

int main(int argc, char **) {
  if (argc != 1) {
    std::cerr << "configuration is read from run.cfg\n";
    return 2;
  }
  try {
    const auto base = pf::executable_directory();
    const auto config = pf::read_config(base / "run.cfg");
    const auto mode = config.contains("mode") ? config.at("mode") : "interpreter";
    const auto program_name =
        config.contains("program") ? config.at("program") : "candidate.pbc";
    if (program_name.empty() || program_name.front() == '/' ||
        program_name.find("..") != std::string::npos) {
      std::cerr << "invalid bytecode\n";
      return 1;
    }
    pf::ParseError parse_error;
    const auto program_file = pf::read_file(base / program_name, 16384);
    const auto program = pf::parse_program(program_file, parse_error);
    const auto snapshot =
        pf::parse_snapshot(pf::read_file(base / "runtime.snap", 65536));
    if (!program || !snapshot) {
      std::cerr << "invalid bytecode\n";
      return 1;
    }
    const bool coarse = config.contains("trace") && config.at("trace") == "coarse";
    auto report = [](std::string_view label, const pf::ExecutionResult &result) {
      std::cout << label << ": "
                << (result.valid && result.terminated ? "completed" : "rejected")
                << ", sink=" << (result.sink_success ? "accepted" : "denied")
                << '\n';
    };
    if (mode == "interpreter") {
      report("reference",
             pf::execute(*program, *snapshot, pf::Tier::Interpreter, nullptr,
                         coarse));
    } else if (mode == "baseline") {
      report("baseline", pf::execute(*program, *snapshot, pf::Tier::Baseline,
                                      nullptr, coarse));
    } else if (mode == "optimizing") {
      const auto name =
          config.contains("profile") ? config.at("profile") : "alpha";
      const auto profile = load_profile(base, name);
      if (!profile)
        throw std::runtime_error("profile");
      report(name, pf::execute(*program, *snapshot, pf::Tier::Optimizing,
                               &*profile, coarse));
    } else if (mode == "all") {
      report("reference",
             pf::execute(*program, *snapshot, pf::Tier::Interpreter, nullptr,
                         coarse));
      for (const std::string name : {"alpha", "beta", "gamma"}) {
        const auto profile = load_profile(base, name);
        if (!profile)
          throw std::runtime_error("profile");
        report(name, pf::execute(*program, *snapshot, pf::Tier::Optimizing,
                                 &*profile, coarse));
      }
    } else {
      throw std::runtime_error("mode");
    }
    return 0;
  } catch (...) {
    std::cerr << "runtime rejected\n";
    return 1;
  }
}
