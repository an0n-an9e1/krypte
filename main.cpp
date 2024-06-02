#include "types.hpp"
#include "constants.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <array>

std::array<unsigned char, 16> generateAESKey() {
  std::array<unsigned char, 16> key;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);
    
  for (auto &byte : key) {
    byte = dis(gen);
  }

  return key;
}

std::array<BYTE, 16> secret;

WORD xorWORD(const WORD& word1, const WORD& word2) {
    WORD result;
    for (u8 i = 0; i < 4; i++) {
        result[i] = word1[i] ^ word2[i];
    }
    return result;
}

WORD g(const WORD& word, const BYTE& round) {
  WORD w1 = {sbox[word[1]], sbox[word[2]], sbox[word[3]], sbox[word[0]]};
  WORD w2 = {RC[round], 0x00, 0x00, 0x00};

  return xorWORD(w1, w2);
}

std::array<WORD, 4> generateRoundKey(const std::array<WORD, 4>& previous, const BYTE& round) {
  std::array<WORD, 4> roundKeys;

  roundKeys[0] = xorWORD(g(previous[3], round), previous[0]);
  roundKeys[1] = xorWORD(roundKeys[0], previous[1]);
  roundKeys[2] = xorWORD(roundKeys[1], previous[2]);
  roundKeys[3] = xorWORD(roundKeys[2], previous[3]);

  return roundKeys;
}


std::array<std::array<WORD, 4>, 11> keyList;

void printKeyList(const std::array<std::array<WORD, 4>, 11>& keyList) {
    for (size_t round = 0; round < keyList.size(); ++round) {
        std::cout << "Round " << round << " Key:" << std::endl;
        for (const auto& word : keyList[round]) {
            for (const auto& byte : word) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }
}

void populateKeys() {
  std::array<WORD, 4> initial;
  initial[0] = { secret[0],  secret[1],  secret[2],  secret[3]};
  initial[1] = { secret[4],  secret[5],  secret[6],  secret[7]};
  initial[2] = { secret[8],  secret[9], secret[10], secret[11]};
  initial[3] = {secret[12], secret[13], secret[14], secret[15]};

  keyList[0] = initial;

  for (u8 i = 1; i <= 10; i++) {
    keyList[i] = generateRoundKey(keyList[i-1], i);
  }
}




// Current state that will be encrypted (128bit block)
BYTE state[4][4];


void populateState(BYTE* data, u64 offset) {
  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      state[i][j] = data[offset + 4*i + j];
    }
  }
}

void populateOutput(BYTE* output, u64 offset) {
  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      output[4*i + j] = state[i][j];
    }
  }
}

void addRoundKey(const u8& round) {
  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      state[i][j] ^= keyList[round][i][j];
    }
  }
}

void subBytes() {
  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      state[i][j] = sbox[state[i][j]];
    }
  }
}

void subBytesInverse() {
  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      state[i][j] = inv_sbox[state[i][j]];
    }
  }
}


void shiftRows() {
  BYTE temp;

  temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;

  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;

  temp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = temp;
}

void shiftRowsInverse() {
    BYTE temp;

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void mixSingleColumn(std::array<BYTE, 4> r) {
  BYTE a[4];
  BYTE b[4];
  u8 c;
  u8 h;

  /* The array 'a' is simply a copy of the input array 'r'
  * The array 'b' is each element of the array 'a' multiplied by 2
  * in Rijndael's Galois field
  * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
  for(c = 0; c < 4; c++) {
    a[c] = r[c];
    /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
    h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
    b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
    b[c] ^= 0x1B & h; /* Rijndael's Galois field */
  }

  r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
  r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
  r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
  r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

void mixColumns() {
  std::array<BYTE, 4> temp;

  for(u8 i = 0; i < 4; i++)
  {
    for(u8 j = 0; j < 4; j++)
    {
      temp[j] = state[j][i];
    }
    
    mixSingleColumn(temp);

    for(u8 j = 0; j < 4; j++)
    {
      state[j][i] = temp[j];
    }
  }
}

BYTE gmul(BYTE a, BYTE b) {
  uint8_t p = 0;
  uint8_t hi_bit_set;
  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set) {
      a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
    }
    b >>= 1;
  }
  return p;
}

void mixSingleColumnInverse(std::array<BYTE, 4> r) {
  static const std::array<BYTE, 4> inv_matrix = {0x0e, 0x0b, 0x0d, 0x09};

  std::array<BYTE, 4> temp;

  for (u8 i = 0; i < 4; i++) {
    temp[i] = gmul(inv_matrix[0], r[i]) ^
              gmul(inv_matrix[1], r[(i + 1) % 4]) ^
              gmul(inv_matrix[2], r[(i + 2) % 4]) ^
              gmul(inv_matrix[3], r[(i + 3) % 4]);
  }

  for (u8 i = 0; i < 4; i++) {
    r[i] = temp[i];
  }
}

void mixColumnsInverse() {
  std::array<BYTE, 4> temp;

  for (u8 i = 0; i < 4; i++) {
    for (u8 j = 0; j < 4; j++) {
      temp[j] = state[j][i];
    }

    mixSingleColumnInverse(temp);

    for (u8 j = 0; j < 4; j++) {
      state[j][i] = temp[j];
    }
  }
}

BYTE* encrypt(BYTE* data, u64 size) {
  BYTE* output = new BYTE(size);

  u64 offset = 0;
  while (offset < size) {
    populateState(data, offset);

    // Round 0:
    addRoundKey(0);
    
    // Rounds 1-9:
    for (u8 i = 0; i < 10; i++) {
      subBytes();
      shiftRows();
      mixColumns();
      addRoundKey(i);
    }

    // Round 10
    subBytes();
    shiftRows();
    addRoundKey(10);
  
    populateOutput(output, offset);


    offset += 16;
  }

  return output;
}

BYTE* decrypt(BYTE* data, u64 size) {
  BYTE* output = new BYTE[size];

  u64 offset = 0;
  while (offset < size) {
    populateState(data, offset);

    // Round 10 (inverse operations)
    addRoundKey(10);
    shiftRowsInverse();
    subBytesInverse();

    // Rounds 9-1 (inverse operations)
    for (u8 i = 9; i > 0; i--) {
      addRoundKey(i);
      mixColumnsInverse();
      shiftRowsInverse();
      subBytesInverse();
    }

    // Round 0 (inverse operation)
    addRoundKey(0);

    populateOutput(output, offset);

    offset += 16;
  }

  return output;
}

BYTE* padData(const BYTE* data, u64& size) {
  u64 newSize = size;
  if (size % 16 != 0) {
    newSize = (size / 16 + 1) * 16;
  }
  BYTE* paddedData = new BYTE[newSize];
  memcpy(paddedData, data, size);
  memset(paddedData + size, 0, newSize - size);  // Pad with zeros
  size = newSize;
  return paddedData;
}

int main() {

  // Check if a key has been generated
  //std::fstream file("./.secret", std::ios::binary);
  //if (not file.good()) {
    //file.close();
    //file.open("./.secret", std::ios::binary | std::ios::out);

    //secret = generateAESKey();
    //file.write(reinterpret_cast<const char*>(secret.data()), secret.size());
    //file.close();
  //}
  //else {
    //file.read(reinterpret_cast<char*>(secret.data()), secret.size());
    //file.close();
  //}  
  //std::cout << "Read AES-128 Key: ";
    //for (const auto &byte : secret) {
        //std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    //}
    //std::cout << std::endl;
  //
  //
  secret = generateAESKey();
  populateKeys();
  
std::string inputText = "0123456789abcdef";  // Example input text

  // Convert text to binary data
  const BYTE* inputData = reinterpret_cast<const BYTE*>(inputText.data());
  u64 dataSize = inputText.size();

  // Pad the data
  BYTE* paddedData = padData(inputData, dataSize);

  // Encrypt the data
  BYTE* encryptedData = encrypt(paddedData, dataSize);

  // Output the encrypted data (for demonstration purposes)
  std::cout << "Encrypted Data:" << std::endl;
  for (u64 i = 0; i < dataSize; ++i) {
    std::cout << std::hex << static_cast<int>(encryptedData[i]) << " ";
  }
  std::cout << std::endl;

  // Decrypt the data
  BYTE* decryptedData = decrypt(encryptedData, dataSize);

  // Output the decrypted data (for demonstration purposes)
  std::cout << "Decrypted Data:" << std::endl;
  for (u64 i = 0; i < dataSize; ++i) {
    std::cout << decryptedData[i];
  }
  std::cout << std::endl;

  // Clean up
  delete[] paddedData;
  delete[] encryptedData;
  delete[] decryptedData;

  return 0;  

}

