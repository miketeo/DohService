/*
 * Copyright (c) 2019 Michael Teo <miketeo@mikteo.net>
 *
 * DohService is provided 'as-is', without any express or implied warranty. In no event will the author be held liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */

#include "includes.h"

// The base64 routines in this file were adapted from
// https://www.mycplus.com/source-code/c-source-code/base64-encode-decode/
// to support base64url in RFC4648

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
static uint8_t decoding_table[256];
static bool has_built_decoding_table = false;

static void build_decoding_table();


uint8_t* base64_decode(const uint8_t *data, size_t input_length, size_t *output_length) {
  if (!has_built_decoding_table) {
    build_decoding_table();
  }

  //if (input_length % 4 != 0) {
  //  return NULL;
  //}

  *output_length = input_length / 4 * 3;
  //if (data[input_length - 1] == '=') (*output_length)--;
  //if (data[input_length - 2] == '=') (*output_length)--;

  uint8_t *decoded_data = calloc(1, *output_length);
  if (decoded_data == NULL) {
    return NULL;
  }

  for (int i = 0, j = 0; i < input_length;) {
    uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

    uint32_t triple = (sextet_a << 3 * 6)
    + (sextet_b << 2 * 6)
    + (sextet_c << 1 * 6)
    + (sextet_d << 0 * 6);

    if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
    if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
    if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
  }

  return decoded_data;
}


static void build_decoding_table() {
  for (int i = 0; i < 64; i++) {
    decoding_table[(uint8_t) encoding_table[i]] = i;
  }
  has_built_decoding_table = true;
}
