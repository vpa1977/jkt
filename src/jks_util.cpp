/*
 * ReadUTF/WriteUTF/convert_to_bytes were copied from java.io.DataInputStream
 *  and java.io.DataOutputStream classes:
 */
/*
 * Copyright (c) 1994, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include "jks_util.h"

#include <stdexcept>

#include "safehandle.h"

#include "jks.h" // for JKS defines

namespace jks
{
namespace util
{

std::vector<uint8_t> convert_to_bytes(const std::u16string &data)
{
	const auto size = data.size();
	std::vector<uint8_t> ret(size * 2);
	for (int i = 0, j = 0; i < size; i++) {
		ret[j++] = data[i] >> 8;
		ret[j++] = data[i];
	}
	return ret;
}

std::vector<uint8_t> JKSCreateDigest(std::span<uint8_t> data,
				     const std::u16string &password)
{
	std::string PASSWORD_SALT = "Mighty Aphrodite";

	EvpMdCtxHandle ctx(EVP_MD_CTX_new());

	if (!EVP_DigestInit(ctx, EVP_sha1()))
		throw std::runtime_error("Unable to init sha1 digest");

	if (!password.empty()) {
		auto passwordBytes = convert_to_bytes(password);
		if (!EVP_DigestUpdate(ctx, passwordBytes.data(),
				      passwordBytes.size()))
			throw std::runtime_error("Unable to hash password");
		if (!EVP_DigestUpdate(ctx, PASSWORD_SALT.data(),
				      PASSWORD_SALT.size()))
			throw std::runtime_error(
				"Unable to hash password salt");
	}

	if (!EVP_DigestUpdate(ctx, std::data(data), data.size()))
		throw std::runtime_error("Unable to hash data");

	std::vector<uint8_t> ret(EVP_MAX_MD_SIZE);
	unsigned int len;

	if (!EVP_DigestFinal(ctx, ret.data(), &len))
		throw std::runtime_error("Unable to create sha1 hash");

	ret.resize(len);
	return ret;
}

std::u16string ReadUTF(std::span<uint8_t> input)
{
	if (input.size() < 3)
		throw std::runtime_error("buffer too short");

	uint16_t utfLen = (input[0] << 8) + input[1];
	std::span<uint8_t> byteArr(input.begin() + 2, input.size() - 2);

	std::u16string charArr;
	charArr.resize(utfLen);

	int c, char2, char3;
	int count = 0;
	int chararr_count = 0;

	while (count < utfLen) {
		c = byteArr[count] & 0xff;
		if (c > 127)
			break;
		count++;
		charArr[chararr_count++] = c;
	}

	while (count < utfLen) {
		c = (int)byteArr[count] & 0xff;
		switch (c >> 4) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7: {
			/* 0xxxxxxx*/
			count++;
			charArr[chararr_count++] = (char)c;
		} break;

		case 12:
		case 13: {
			/* 110x xxxx   10xx xxxx*/
			count += 2;
			if (count > utfLen)
				throw std::runtime_error(
					"malformed input: partial character at end");
			char2 = byteArr[count - 1];
			if ((char2 & 0xC0) != 0x80)
				throw std::runtime_error(
					"malformed input around byte ");
			charArr[chararr_count++] =
				(((c & 0x1F) << 6) | (char2 & 0x3F));
		} break;
		case 14: {
			/* 1110 xxxx  10xx xxxx  10xx xxxx */
			count += 3;
			if (count > utfLen)
				std::runtime_error(
					"malformed input: partial character at end");
			char2 = byteArr[count - 2];
			char3 = byteArr[count - 1];
			if (((char2 & 0xC0) != 0x80) ||
			    ((char3 & 0xC0) != 0x80))
				throw std::runtime_error(
					"malformed input around byte ");
			charArr[chararr_count++] =
				(((c & 0x0F) << 12) | ((char2 & 0x3F) << 6) |
				 ((char3 & 0x3F) << 0));
		} break;
		default:
			/* 10xx xxxx,  1111 xxxx */
			throw std::runtime_error(
				"malformed input around byte " + count);
		}
	}
	// The number of chars produced may be less than utfLen
	charArr.resize(chararr_count);
	return charArr;
}

std::vector<uint8_t> convert_utf(const std::u16string &str)
{
	auto strlen = str.size();
	auto utflen = strlen;
	for (int i = 0; i < strlen; i++) {
		auto c = str[i];
		if (c >= 0x80 || c == 0)
			utflen += (c >= 0x800) ? 2 : 1;
	}
	if (utflen > 65535 || /* overflow */ utflen < strlen)
		throw std::runtime_error("string is too long");

	std::vector<uint8_t> bytearr(utflen + 2);

	int count = 0;
	bytearr[count++] = (uint8_t)((utflen >> 8) & 0xFF);
	bytearr[count++] = (uint8_t)((utflen >> 0) & 0xFF);

	int i = 0;
	for (i = 0; i < strlen; i++) { // optimized for initial run of ASCII
		auto c = str[i];
		if (c >= 0x80 || c == 0)
			break;
		bytearr[count++] = c;
	}

	for (; i < strlen; i++) {
		auto c = str[i];
		if (c < 0x80 && c != 0) {
			bytearr[count++] = (uint8_t)c;
		} else if (c >= 0x800) {
			bytearr[count++] = (uint8_t)(0xE0 | ((c >> 12) & 0x0F));
			bytearr[count++] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
			bytearr[count++] = (uint8_t)(0x80 | ((c >> 0) & 0x3F));
		} else {
			bytearr[count++] = (uint8_t)(0xC0 | ((c >> 6) & 0x1F));
			bytearr[count++] = (uint8_t)(0x80 | ((c >> 0) & 0x3F));
		}
	}
	return bytearr;
}

std::u16string ReadUTF(std::istream &is)
{
	std::vector<uint8_t> input(2);
	is >> input[0];
	is >> input[1];
	uint16_t utfLen = (input[0] << 8) + input[1];
	input.resize(utfLen + input.size());
	is.read(reinterpret_cast<char *>(input.data() + 2), utfLen);
	return ReadUTF(input);
}

void WriteUTF(std::ostream &os, const std::u16string &data)
{
	auto ret = convert_utf(data);
	os.write(reinterpret_cast<char *>(ret.data()), ret.size());
}

}
}
