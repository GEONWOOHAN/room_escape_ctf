#include "core.hpp"

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>

std::string hex(const pf::Digest &digest) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : digest)
    out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

int main() {
  const pf::Bytes empty;
  const pf::Bytes abc{'a', 'b', 'c'};
  if (hex(pf::blake3_small(empty)) !=
          "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" ||
      hex(pf::blake3_small(abc)) !=
          "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85") {
    std::cerr << "BLAKE3 vector failed\n";
    return 1;
  }
  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 24> nonce{};
  for (std::size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<std::uint8_t>(i);
  for (std::size_t i = 0; i < nonce.size(); ++i)
    nonce[i] = static_cast<std::uint8_t>(0xa0 + i);
  const pf::Bytes plaintext{'t', 'e', 's', 't'};
  const pf::Bytes aad{'a', 'a', 'd'};
  const auto encrypted =
      pf::xchacha20poly1305_encrypt(plaintext, key, nonce, aad);
  const auto decrypted =
      pf::xchacha20poly1305_decrypt(encrypted, key, nonce, aad);
  if (!decrypted || *decrypted != plaintext) {
    std::cerr << "XChaCha20-Poly1305 round trip failed\n";
    return 1;
  }
  std::cout << "crypto vectors passed\n";
  return 0;
}
