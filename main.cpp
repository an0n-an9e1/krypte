#include "types.hpp"
#include "constants.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <array>
#include <string>
#include <bits/stdc++.h>


// The secret key
std::array<BYTE, 16> skey;


// The expanded secret key
std::array<std::array<BYTE, 16>, 11> keys;

// The current block of data that is being encrypted/decrypted
BLOCK state;




WORD xorWORD(const WORD& w1, const WORD& w2) {
	WORD result;

	for (u8 i = 0; i < 4; i++) {
		result[i] = w1[i] ^ w2[i];
	}

	return result;
}

BLOCK xorBLOCK(const BLOCK& b1, const BLOCK& b2) {
	BLOCK result;

	for (u8 i = 0; i < 16; i++) {
		result[i] = b1[i] ^ b2[i];
	}

	return result;
}





void populateKeys(const std::array<BYTE, 16>& secret) {
	keys[0] = secret;

	WORD last;
	for (u8 j = 0; j < 4; j++) {
		last[j] = keys[0][j + 12];
	}

	for (u8 i = 1; i <= 10; i++) {
		// g():
		WORD transformed = {sbox[(last[1])], sbox[(last[2])], sbox[(last[3])], sbox[(last[0])]};
		WORD roundconst =  {rcon[i], 0x00, 0x00, 0x00};
		last = xorWORD(transformed, roundconst);
		
		// w[0]:
		keys[i][0] = keys[i-1][0] ^ last[0];
		keys[i][1] = keys[i-1][1] ^ last[1];
		keys[i][2] = keys[i-1][2] ^ last[2];
		keys[i][3] = keys[i-1][3] ^ last[3];

		// w[1]:
		keys[i][4] = keys[i-1][4] ^ keys[i][0];
		keys[i][5] = keys[i-1][5] ^ keys[i][1];
		keys[i][6] = keys[i-1][6] ^ keys[i][2];
		keys[i][7] = keys[i-1][7] ^ keys[i][3];

		// w[2]:
		keys[i][8]  = keys[i-1][8]  ^ keys[i][4];
		keys[i][9]  = keys[i-1][9]  ^ keys[i][5];
		keys[i][10] = keys[i-1][10] ^ keys[i][6];
		keys[i][11] = keys[i-1][11] ^ keys[i][7];

		// w[3]:
		keys[i][12] = keys[i-1][12] ^ keys[i][8];
		keys[i][13] = keys[i-1][13] ^ keys[i][9];
		keys[i][14] = keys[i-1][14] ^ keys[i][10];
		keys[i][15] = keys[i-1][15] ^ keys[i][11];

		// Restore last:
		for (u8 j = 0; j < 4; j++) {
			last[j] = keys[i][j + 12];
		}
	}
}


void printKeys(const std::array<std::array<BYTE, 16>, 11>& keys) {
    for (const auto& row : keys) {
        for (const auto& byte : row) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
}



void SubBytes() {
	for (u8 i = 0; i < 16; i++) {
		state[i] = sbox[(state[i])];
	}
}

void InvSubBytes() {
	for (u8 i = 0; i < 16; i++) {
		state[i] = inv_sbox[(state[i])];
	}
}




void ShiftRows() {
	BYTE temp;
	
	temp = state[4];
	state[4] = state[5];
	state[5] = state[6];
	state[6] = state[7];
	state[7] = temp;

	std::swap(state[8], state[10]);
	std::swap(state[9], state[11]);

	temp = state[15];
	state[15] = state[14];
	state[14] = state[13];
	state[13] = state[12];
	state[12] = temp;
}

void InvShiftRows() {
	BYTE temp;

	temp = state[7];
	state[7] = state[6];
	state[6] = state[5];
	state[5] = state[4];
	state[4] = temp;

	std::swap(state[11], state[9]);
	std::swap(state[10], state[8]);

	temp = state[12];
	state[12] = state[13];
	state[13] = state[14];
	state[14] = state[15];
	state[15] = temp;
}


void MixColumn(BYTE* d0, BYTE* d1, BYTE* d2, BYTE* d3) {
	const BYTE b[4] = {*d0, *d1, *d2, *d3};

	*d0 = gmul2[(b[0])] ^ gmul3[(b[1])] ^ (b[2]) ^ (b[3]);
	*d1 = (b[0]) ^ gmul2[(b[1])] ^ gmul3[(b[2])] ^ (b[3]);
	*d2 = (b[0]) ^ (b[1]) ^ gmul2[(b[2])] ^ gmul3[(b[3])];
	*d3 = gmul3[(b[0])] ^ (b[1]) ^ (b[2]) ^ gmul2[(b[3])];
}

void MixColumns() {
	MixColumn(&state[0], &state[4], &state[8],  &state[12]);
	MixColumn(&state[1], &state[5], &state[9],  &state[13]);
	MixColumn(&state[2], &state[6], &state[10], &state[14]);
	MixColumn(&state[3], &state[7], &state[11], &state[15]);
}

void InvMixColumn(BYTE* b0, BYTE* b1, BYTE* b2, BYTE* b3) {
	const BYTE d[4] = {*b0, *b1, *b2, *b3};

	*b0 = gmul14[(d[0])] ^ gmul11[(d[1])] ^ gmul13[(d[2])] ^ gmul9[(d[3])];
	*b1 = gmul9[(d[0])] ^ gmul14[(d[1])] ^ gmul11[(d[2])] ^ gmul13[(d[3])];
	*b2 = gmul13[(d[0])] ^ gmul9[(d[1])] ^ gmul14[(d[2])] ^ gmul11[(d[3])];
	*b3 = gmul11[(d[0])] ^ gmul13[(d[1])] ^ gmul9[(d[2])] ^ gmul14[(d[3])];
}

void InvMixColumns() {
	InvMixColumn(&state[0], &state[4], &state[8],  &state[12]);
	InvMixColumn(&state[1], &state[5], &state[9],  &state[13]);
	InvMixColumn(&state[2], &state[6], &state[10], &state[14]);
	InvMixColumn(&state[3], &state[7], &state[11], &state[15]);
}


void PopulateState(BYTE* data, u64 offset) {
  for (u8 i = 0; i < 16; i++) {
    state[i] = *(offset + data + i);
  }
}

void PopulateOutput(BYTE* data, u64 offset) {
  for (u8 i = 0; i < 16; i++) {
    *(offset + data + i) = state[i];
  }
}

void printState() {
  for (size_t i = 0; i < 4; ++i) {
    for (size_t j = 0; j < 4; ++j) {
      std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(state[i * 4 + j]) << " ";
    }
    std::cout << std::endl;
  }
}

void encrypt(BYTE* data, BYTE* encrypted, u64 size) {
  u64 offset = 0;


  while (offset < size) {
    PopulateState(data, offset);

    // Round 0:
    state = xorBLOCK(state, keys[0]);
    
    // Rounds 1-9:
    for (u8 i = 1; i <= 9; i++) {
      SubBytes();
      ShiftRows();
      MixColumns();
      state = xorBLOCK(state, keys[i]);
    }

    // Round 10
    SubBytes();
    ShiftRows();
    state = xorBLOCK(state, keys[10]);

    PopulateOutput(encrypted, offset);

    offset += 16;
  }
}


void decrypt(BYTE* data, BYTE* decrypted, u64 size) {
  u64 offset = 0;

  while (offset < size) {
    PopulateState(data, offset);

    // Round 10:
    state = xorBLOCK(state, keys[10]);
    InvShiftRows();
    InvSubBytes();

    // Rounds 9-1:
    for (u8 i = 9; i >= 1; i--) {
      state = xorBLOCK(state, keys[i]);
      InvMixColumns();
      InvShiftRows();
      InvSubBytes();
    }

    // Round 0:
    state = xorBLOCK(state, keys[0]);

    PopulateOutput(decrypted, offset);

    offset += 16;
  }
}


bool setSecret(const char* key) {
  if (strlen(key) != 32) {
    return false;
  }

  for (u8 i = 0; i < 16; i++) {
    BYTE hex1 = key[2*i];
    BYTE hex2 = key[2*i + 1];

    if (hex1 >= '0' && hex1 <= '9') {
        hex1 =  hex1 - '0';
    } else if (hex1 >= 'a' && hex1 <= 'f') {
        hex1 = hex1 - 'a' + 10;
    } else if (hex1 >= 'A' && hex1 <= 'F') {
        hex1 = hex1 - 'A' + 10;
    } else {
      return false;
    }

    if (hex2 >= '0' && hex2 <= '9') {
        hex2 =  hex2 - '0';
    } else if (hex2 >= 'a' && hex2 <= 'f') {
        hex2 = hex2 - 'a' + 10;
    } else if (hex2 >= 'A' && hex2 <= 'F') {
        hex2 = hex2 - 'A' + 10;
    } else {
      return false;
    }

    skey[i] = 16*hex1 + hex2;
  }

  return true;
}


bool getKey() {
  const std::string filename = std::string(getenv("HOME")) + "/.secret";
  std::ifstream file(filename);


  if (!file.is_open()) {
      return false; 
  }

  std::string key;
  file >> key;

  if (!file.good() || key.length() != 32) {
    return false;
  }

  return setSecret(key.c_str());
}


bool fileExists(const std::string& filename) {
  std::ifstream file(filename);
  return file.good();
}

std::string generateUniqueFilename(const std::string& originalFilename) {
    std::string newFilename = originalFilename + ".lock";
    int counter = 1;

    // While the file with the newFilename exists, keep modifying it
    while (fileExists(newFilename)) {
        std::ostringstream oss;
        oss << originalFilename << "_" << counter++ << ".lock";
        newFilename = oss.str();
    }

    return newFilename;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cout << "error: No arguments provided!" << std::endl;

    return -1;
  }

  if (strcmp(argv[1], "encrypt") == 0) {
    if (argc == 2) {
      std::cout << "error: Too few arguments provided! Try entering a file to encrypt!" << std::endl;

      return -1;
    }

    std::string filename = argv[2];
    
    // Step 0: Check if a key has been provided and if destructive mode has been set
    // Step 1: Check if file exists
    // Step 2: Read the binary data of the file in a variable
    // Step 3: Pad the data to make it into 128bit blocks
    // Step 4: encrypt
    // Step 5: Either create a new file and write the encrypted data or delete the data on the file and write over it
    

    bool destructive = false;

    if (argc >= 4) {
      if (strcmp(argv[3], "-k") == 0) {
        if (argc < 5) {
          std::cout << "error: Key not provided!" << std::endl;

          return -1;
        }

        if (not setSecret(argv[4])) {
          std::cout << "error: The key provided is not a valid key!" << std::endl;

          return -1;
        }

        if (argc > 5) {
          if (strcmp(argv[5], "-d") == 0) {
            destructive = true;
          }
          else {
            std::cout << "error: The argument " << argv[5] << " is invalid!" << std::endl;

            return -1;
          }
          
          if (argc > 6) {
            std::cout << "error: Too many arguments provided!" << std::endl;

            return -1;
          }
        }
      }
      else if (strcmp(argv[3], "-d") == 0) {
        destructive = true;
        if (not getKey()) {
          std::cout << "error: The default key has not been set yet. Please set that before using this method!" << std::endl;

          return -1;
        }

        if (argc > 5) {
          std::cout << "error: Too many arguments provided!" << std::endl;

          return -1;
        }
      }
      else {
        std::cout << "error: The argument " << argv[3] << " is invalid!" << std::endl;

        return -1;
      }
    }



    std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
      std::cout << "error: Specified file does not exist!" << std::endl;

      return -1;
    }

    BYTE* data = nullptr;
    u64 size = 0;
    
    size = file.tellg();
    file.seekg(0, std::ios::beg);
    // Auto Padding may be the issue in the future
    u8 add = 0;
    if (not (size % 16 == 0)) {
      add = 16 - size%16;
      size += add;
    }


    data = new BYTE[size];
    file.read(reinterpret_cast<char*>(data), size);
    file.close();

    for (u8 i = 1; i <= add; i++) {
      data[size-i] = 0;
    }

    BYTE* encrypted = new BYTE[size];

    encrypt(data, encrypted, size);
    

    if (destructive) {
      std::ofstream file_o(argv[2], std::ios::binary);
      file_o.write(reinterpret_cast<const char*>(encrypted), size);
      file_o.close();

    }
    else {
      std::ofstream file_o(generateUniqueFilename(argv[2]), std::ios::binary);
      if (!file_o.is_open()) {
        std::cout << "error: Problems with opening the file!" << std::endl;

        return -1;
      }

      file_o.write(reinterpret_cast<const char*>(encrypted), size);
      file_o.close();
    }
    

  }
  else if (strcmp(argv[1], "decrypt") == 0) {
    if (argc == 2) {
      std::cout << "error: Too few arguments provided! Try entering a file to encrypt!" << std::endl;

      return -1;
    }

    std::string filename = argv[2];
    
    // Step 0: Check if a key has been provided and if destructive mode has been set
    // Step 1: Check if file exists
    // Step 2: Read the binary data of the file in a variable
    // Step 3: Pad the data to make it into 128bit blocks
    // Step 4: decrypt
    // Step 5: Either create a new file and write the encrypted data or delete the data on the file and write over it
    

    bool destructive = false;

    if (argc >= 4) {
      if (strcmp(argv[3], "-k") == 0) {
        if (argc < 5) {
          std::cout << "error: Key not provided!" << std::endl;

          return -1;
        }

        if (not setSecret(argv[4])) {
          std::cout << "error: The key provided is not a valid key!" << std::endl;

          return -1;
        }

        if (argc > 5) {
          if (strcmp(argv[5], "-d") == 0) {
            destructive = true;
          }
          else {
            std::cout << "error: The argument " << argv[5] << " is invalid!" << std::endl;

            return -1;
          }
          
          if (argc > 6) {
            std::cout << "error: Too many arguments provided!" << std::endl;

            return -1;
          }
        }
      }
      else if (strcmp(argv[3], "-d") == 0) {
        destructive = true;
        if (not getKey()) {
          std::cout << "error: The default key has not been set yet. Please set that before using this method!" << std::endl;

          return -1;
        }

        if (argc > 5) {
          std::cout << "error: Too many arguments provided!" << std::endl;

          return -1;
        }
      }
      else {
        std::cout << "error: The argument " << argv[3] << " is invalid!" << std::endl;

        return -1;
      }
    }

    std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
      std::cout << "error: Specified file does not exist!" << std::endl;

      return -1;
    }

    BYTE* data = nullptr;
    u64 size = 0;
    
    size = file.tellg();
    file.seekg(0, std::ios::beg);

    data = new BYTE[size];
    file.read(reinterpret_cast<char*>(data), size);
    file.close();

    BYTE* decrypted = new BYTE[size];

    decrypt(data, decrypted, size);
    

    if (destructive) {
      std::ofstream file_o(argv[2], std::ios::binary);
      file_o.write(reinterpret_cast<const char*>(decrypted), size);
      file_o.close();

    }
    else {
      std::ofstream file_o(generateUniqueFilename(argv[2]), std::ios::binary);
      if (!file_o.is_open()) {
        std::cout << "error: Problems with opening the file!" << std::endl;

        return -1;
      }

      file_o.write(reinterpret_cast<const char*>(decrypted), size);
      file_o.close();
    }
  }
  else {
    if (strcmp(argv[1], "-v") == 0) {
      std::cout << "Krypte encryption/decryptio software v0.1.0" << std::endl;

      return 0;
    }
    else if (strcmp(argv[1], "-h") == 0) {
      std::cout << "Usage: krypte encrypt <filename> -k <secret_key>" << "\n";
      std::cout << "Modes: " << "\n" << "\tencrypt - used to encrypt files" << "\n"
                                     << "\tdecrypt - used to decrypt files" << "\n";
      std::cout << "Options:" << "\n"
                << "\t-v       - shows the version of the software" << "\n"
                << "\t-h       - prints this help screen" << "\n"
                << "\t-genkey  - used to create a default secret key for encryption/decryption without providing a key everytime" << "\n"
                << "\t-setkey  - used to set the default secret key for encryption/decryption without providing a key everytime" << "\n"
                << "\t-k <key> - used to provide a 128bit key for the current encryption/decryption of the file" << "\n"
                << "\t-d       - used to set the mode to destryctive meaning that the file provided will be erased and will be filled with the content of the encryption/decryption" << "\n";

      std::cout << std::endl;

      return 0;
    }
    else {
      std::cout << "error: The argument " << argv[1] << " is invalid!" << std::endl;

      return -1;
    }
  }


  return 0; 
}

