#include <cstdio>
#include <array>

using Enc = std::array<unsigned char, 32>;
using Group = std::array<unsigned char, 3>;

Enc EncodeX(Group grp) {
  auto xout = Enc{};
  constexpr char const *kStr = "a#s224kfuSaom=D469asSkOdhmP34!@-";
  constexpr size_t kStrLen = 32;

  for (auto i = 0u; i < grp.size(); i++)
    grp[i] = (char)(grp[i] % 10);

  for (int i = 0; i < 32; i++) {
    int f24 = i % grp.size();      // 3 mod
    int f16 = i % kStrLen;         // 3 mod
    int f17 = f16 + grp[f24];      // 4 div pls
    int f18 = f17 % kStr[f16];     // 1 pls mod
    int f21 = f17 * f18;           // 2 mul
    int f20 = f18 ^ kStr[f24];     // 5 xor
    int f15 = f21 + f20;           // 4 div pls
    xout[i] = (char)(f15 & 255);
  }
  return xout;
}

Enc EncodeY(const Enc &xin, Group grp) {
  auto yout = Enc{};
  constexpr char const *kStr = "0123456789ABCDEF";

  for (auto i = 0u; i < grp.size(); i++) grp[i] = (char) ((grp[i] / 10) % 10);
  for (int i = 0u; i < 32; i++) {
    auto n = (grp[i % grp.size()] + xin[i]) % 16;
    yout[i] = kStr[n];
  }
  return yout;
}

Enc Encode(Group grp) {
  return EncodeY(EncodeX(grp), grp);
}

void Check(const Group &grp) {
  static const char* kStrs[] = {"6F50D5057EFB2B9411C1B237E7D8588D", "98DD67FE3789D499AB3AF3CD1055EB76", "10556D767F835C91A9B2BBCF98DDE4FE", "72AD4A98C3603EE1865407ACFA25C210"};
  auto enc = Encode(grp);
  for (const auto &str: kStrs) {
    if (std::equal(std::begin(enc), std::end(enc), str)) {
      printf("%s %s\n", std::string(std::begin(grp), std::end(grp)).c_str(), str);
    }
  }
}

void Bruteforce() {
  const auto begin = ' ', end = '\x7f';
  auto grp = Group{};
  for (auto f24 = begin; f24 < end; ++f24) {
    grp[0] = f24;
    for (auto f16 = begin; f16 < end; ++f16) {
      grp[1] = f16;
      for (auto z = begin; z < end; ++z) {
        grp[2] = z;
        Check(grp);
      }
    }
  }
}

void Test() {
  auto grp = Group{'a', 'a', 'a'};
  auto enc = Encode(grp);
  printf("%s\n", std::string(std::begin(enc), std::end(enc)).c_str());
}

/*
  2S1 6F50D5057EFB2B9411C1B237E7D8588D
  Qql 98DD67FE3789D499AB3AF3CD1055EB76
  mql 98DD67FE3789D499AB3AF3CD1055EB76
  Y9i 10556D767F835C91A9B2BBCF98DDE4FE
  e9i 10556D767F835C91A9B2BBCF98DDE4FE
  f_o 72AD4A98C3603EE1865407ACFA25C210

  RCTF{2S1 x y f_o}
  RCTF{2S1QqlY9if_o}
  RCTF{2S1mqlY9if_o}
  RCTF{2S1Qqle9if_o}

  RCTF{2S1mqle9if_o}
 */


int main() {
  // 2S1
  Bruteforce();
  return 0;
}
