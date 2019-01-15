

#include "Base64RK.h"

//const char *Base64::encodeTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char *Base64::encodeTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// This can be made more efficient by making a 256-byte decodeTable, but the 96 byte version is still
// quite efficient and saves code space
const uint8_t Base64::decodeTable[96] = {
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
		64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
		64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

// [static]
bool Base64::encode(const uint8_t *src, size_t srcLen, char *dst, size_t &dstLen, bool nullTerminate) {

	if (dstLen < getEncodedSize(srcLen, nullTerminate)) {
		return false;
	}

	size_t ii = 0;
	char *p = dst;
	if (srcLen >= 3) {
		for (ii = 0; ii < srcLen - 2; ii += 3) {
			*p++ = encodeTable[(src[ii] >> 2) & 0x3F];
			*p++ = encodeTable[((src[ii] & 0x3) << 4) | ((src[ii + 1] & 0xF0) >> 4)];
			*p++ = encodeTable[((src[ii + 1] & 0xF) << 2) | ((src[ii + 2] & 0xC0) >> 6)];
			*p++ = encodeTable[src[ii + 2] & 0x3F];
		}
	}

	if (ii < srcLen) {
		*p++ = encodeTable[(src[ii] >> 2) & 0x3F];
		if (ii == (srcLen - 1)) {
			*p++ = encodeTable[((src[ii] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = encodeTable[((src[ii] & 0x3) << 4) | ((src[ii + 1] & 0xF0) >> 4)];
			*p++ = encodeTable[((src[ii + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	if (nullTerminate) {
		*p = 0;
	}

	dstLen = p - dst;

	return true;
}

// [static]
size_t Base64::getEncodedSize(size_t srcLen, bool nullTerminate) {
	size_t size;

	if (srcLen > 0) {
		// Number of triplets rounded up, because of padding
		size_t numTriplets = (srcLen + 2) / 3;

		size = numTriplets * 4;
	}
	else {
		size = 0;
	}

	if (nullTerminate) {
		size++;
	}

	return size;
}

// [static]
String Base64::encodeToString(const uint8_t *src, size_t srcLen) {
	String result;

	result.reserve(getEncodedSize(srcLen, true));

	size_t ii = 0;
	if (srcLen >= 3) {
		for (ii = 0; ii < srcLen - 2; ii += 3) {
			result.concat(encodeTable[(src[ii] >> 2) & 0x3f]);
			result.concat(encodeTable[((src[ii] & 0x3) << 4) | ((src[ii + 1] & 0xf0) >> 4)]);
			result.concat(encodeTable[((src[ii + 1] & 0xf) << 2) | ((src[ii + 2] & 0xc0) >> 6)]);
			result.concat(encodeTable[src[ii + 2] & 0x3f]);
		}
	}

	if (ii < srcLen) {
		result.concat(encodeTable[(src[ii] >> 2) & 0x3f]);
		if (ii == (srcLen - 1)) {
			result.concat(encodeTable[((src[ii] & 0x3) << 4)]);
			result.concat('=');
		}
		else {
			result.concat(encodeTable[((src[ii] & 0x3) << 4) | ((src[ii + 1] & 0xf0) >> 4)]);
			result.concat(encodeTable[((src[ii + 1] & 0xf) << 2)]);
		}
		result.concat('=');
	}

	return result;
}

// [static]
bool Base64::decode(const char *src, uint8_t *dst, size_t &dstLen) {
	return decode(src, strlen(src), dst, dstLen);
}

// [static]
bool Base64::decode(const char *src, size_t srcLen, uint8_t *dst, size_t &dstLen) {
	int srcLeft;

	// Make sure input is valid
	for(size_t ii = 0; ii < srcLen; ii++) {
		if (src[ii] == '=') {
			// Start of padding, ignore the rest of the bytes
			srcLen = ii;
			break;
		}
		// src is signed char, so high-bit set values will be negative and caught by the < 0x20 test
		if (src[ii] < 0x20 || decodeTable[src[ii] - 0x20] == 64) {
			return false;
		}
	}

	// Makes sure destination is at least long enough for the number of integral quads;
	// the remainder part is checked for below once we know the actual length
	if (dstLen < ((srcLen / 4) * 3)) {
		return false;
	}
	srcLeft = srcLen;

	uint8_t *dstCur = dst;
	uint8_t *dstEnd = &dst[dstLen];

	while (srcLeft > 4) {
		*dstCur++ = (uint8_t) (decodeTable[*src - 0x20] << 2 | decodeTable[src[1] - 0x20] >> 4);
		*dstCur++ = (uint8_t) (decodeTable[src[1] - 0x20] << 4 | decodeTable[src[2] - 0x20] >> 2);
		*dstCur++ = (uint8_t) (decodeTable[src[2] - 0x20] << 6 | decodeTable[src[3] - 0x20]);
		src += 4;
		srcLeft -= 4;
	}

	if (srcLeft > 1) {
		if (dstCur >= dstEnd) {
			return false;
		}
		*dstCur++ = (unsigned char) (decodeTable[*src - 0x20] << 2 | decodeTable[src[1] - 0x20] >> 4);
	}
	if (srcLeft > 2) {
		if (dstCur >= dstEnd) {
			return false;
		}
		*dstCur++ = (unsigned char) (decodeTable[src[1] - 0x20] << 4 | decodeTable[src[2] - 0x20] >> 2);
	}
	if (srcLeft > 3) {
		if (dstCur >= dstEnd) {
			return false;
		}
		*dstCur++ = (unsigned char) (decodeTable[src[2] - 0x20] << 6 | decodeTable[src[3] - 0x20]);
	}
	dstLen = dstCur - dst;

	return true;
}

// [static]
size_t Base64::getMaxDecodedSize(size_t srcLen) {
	size_t numQuads = srcLen / 4;

	return numQuads * 3;
}
