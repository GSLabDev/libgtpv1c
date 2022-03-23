/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ENC_DEC_BITS_H__
#define __ENC_DEC_BITS_H__

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief  : decode bits recived from network.
 * @param  : source, buffer need to be decoded
 * @param  : offset, offset from where we had to decode the buffer.
 * @param  : bit_count, number of bits need to decoded.
 * @param  : decoded_bit_count, number of bits decoded.
 * @return : the value after decoding the number of bits.
 */
uint64_t decode_bits(const uint8_t source[], const uint16_t offset, 
	const uint16_t bit_count, uint16_t *decoded_bit_count);


/*
 * @brief  : encode bits to be send on network.
 * @param  : value, value need to be encoded
 * @param  : bit_count, number of bits to be encoded.
 * @param  : destination, buffer to store encoded bits.
 * @param  : offset, buffer's offset for storing.
 * @return : number of encoded bits.
 */
uint16_t encode_bits(const uint64_t value, const uint16_t bit_count, 
	uint8_t destination[], const uint16_t offset);

#ifdef __cplusplus
}
#endif

#endif /* __ENC_DEC_BITS_H__ */
