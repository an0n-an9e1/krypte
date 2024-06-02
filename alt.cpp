#include "types.hpp"
#include "constants.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <array>
#include <bits/stdc++.h>


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
  std::memcpy(state.data(), data + offset, 16);
}

void PopulateOutput(BYTE* data, u64 offset) {
  std::memcpy(data + offset, state.data(), 16);
}


void encrypt(BYTE* data, BYTE* encrypted, u64 size) {
  u64 offset = 0;


  while (offset < size) {
    PopulateState(data, offset);

    // Round 0:
    xorBLOCK(state, keys[0]);
    
    // Rounds 1-9:
    for (u8 i = 0; i < 10; i++) {
      SubBytes();
      ShiftRows();
      MixColumns();
      xorBLOCK(state, keys[i]);
    }

    // Round 10
    SubBytes();
    ShiftRows();
    xorBLOCK(state, keys[10]);

    PopulateOutput(encrypted, offset);

    offset += 16;
  }
}


void decrypt(BYTE* data, BYTE* decrypted, u64 size) {
  u64 offset = 0;

  while (offset < size) {
    PopulateState(data, offset);

    // Round 10:
    xorBLOCK(state, keys[10]);
    InvShiftRows();
    InvSubBytes();

    // Rounds 9-1:
    for (u8 i = 9; i > 0; i--) {
      xorBLOCK(state, keys[i]);
      InvMixColumns();
      InvShiftRows();
      InvSubBytes();
    }

    // Round 0:
    xorBLOCK(state, keys[0]);

    PopulateOutput(decrypted, offset);

    offset += 16;
  }
}


int main() {

	populateKeys({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
	printKeys(keys);

    const char* input = "0123456789abcdef";
    u64 inputSize = std::strlen(input);

      
    std::cout << "Entered data: ";
    for (int i = 0; i < inputSize; i++) {
      std::cout << input[i];
    }
    std::cout << std::endl;

    // Allocate memory for data and encrypted arrays
    BYTE* data = new BYTE[inputSize];
    BYTE* encrypted = new BYTE[inputSize];

    // Copy input data to data array
    std::memcpy(data, input, inputSize);

    // Perform encryption
    encrypt(data, encrypted, inputSize);

    // Print encrypted data
    std::cout << "Encrypted data:" << std::endl;
    for (u64 i = 0; i < inputSize; ++i) {
        std::cout << static_cast<int>(encrypted[i]) << " ";
    }
    std::cout << std::endl;

    BYTE* decryptedData = new BYTE[inputSize];

    // Perform decryption
    decrypt(encrypted, decryptedData, inputSize);

    // Print decrypted data
    std::cout << "Decrypted data:" << std::endl;
    for (u64 i = 0; i < inputSize; ++i) {
        std::cout << static_cast<char>(decryptedData[i]);
    }
    std::cout << std::endl;


    return 0; 

}

