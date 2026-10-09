#include "engine.hpp"

#include <algorithm>
#include <iostream>

int main(int argc, char **) {
  if (argc != 1)
    return 2;
  try {
    const auto base = pf::executable_directory();
    const auto receipt =
        pf::parse_receipt(pf::read_file(base / "receipt.bin", 65536));
    const auto encrypted =
        pf::parse_encrypted_flag(pf::read_file(base / "flag.enc", 65536));
    const auto snapshot =
        pf::parse_snapshot(pf::read_file(base / "runtime.snap", 65536));
    pf::ParseError parse_error;
    const auto program = pf::parse_program(
        pf::read_file(base / "candidate.pbc", 16384), parse_error);
    const auto commitment = pf::read_file(base / "transcript.commit", 32);
    if (!receipt || !encrypted || !snapshot || !program ||
        commitment.size() != 32 ||
        receipt->program_checksum != pf::program_structural_hash(*program))
      throw std::runtime_error("proof");
    const auto transcript_hash = pf::sha256(receipt->raw_transcript);
    if (!std::equal(transcript_hash.begin(), transcript_hash.end(),
                    commitment.begin()))
      throw std::runtime_error("commitment");
    const auto records = pf::parse_transcript(receipt->raw_transcript);
    if (!records)
      throw std::runtime_error("transcript");
    auto root = std::find_if(snapshot->capabilities.begin(),
                             snapshot->capabilities.end(), [](const auto &cap) {
                               return (cap.rights & 0x80000000u) != 0;
                             });
    if (root == snapshot->capabilities.end())
      throw std::runtime_error("root");
    for (std::size_t i = 0; i < 3; ++i) {
      if (receipt->seals[i] !=
          pf::compute_seal(*root, pf::kSealMessage, (*records)[i]))
        throw std::runtime_error("seal");
    }
    const auto key = pf::derive_flag_key(receipt->raw_transcript,
                                         receipt->seals, encrypted->salt);
    const auto plaintext = pf::xchacha20poly1305_decrypt(
        encrypted->ciphertext_and_tag, key, encrypted->nonce, encrypted->aad);
    const bool flag_prefix = plaintext && plaintext->size() >= 7 &&
        ((plaintext->size() >= 5 &&
          std::equal(plaintext->begin(), plaintext->begin() + 5,
                     std::array<std::uint8_t, 5>{'F', 'L', 'A', 'G', '{'}.begin())) ||
         (plaintext->size() >= 4 &&
          std::equal(plaintext->begin(), plaintext->begin() + 4,
                     std::array<std::uint8_t, 4>{'S', 'H', 'A', '{'}.begin())));
    if (!flag_prefix || plaintext->back() != '}')
      throw std::runtime_error("aead");
    std::cout.write(reinterpret_cast<const char *>(plaintext->data()),
                    plaintext->size());
    std::cout << '\n';
    return 0;
  } catch (...) {
    std::cerr << "invalid proof\n";
    return 1;
  }
}
