/* 
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/

// 2016, Amirali Sanatinia (amirali@ccs.neu.edu)

#include <string.h>
#include <iaesni.h>
#include "iaes_asm_interface.h"

#ifdef _WIN32
    #include <intrin.h> /* __cpuid */
#else
    #include <cpuid.h>
#endif

#if defined(_WIN32)
    #include <malloc.h>
#else
    #include <alloca.h>
    #ifndef _alloca
        #define _alloca alloca
    #endif
#endif

#define BLOCK_SIZE (16) //in bytes
#define AES_128_KEYSIZE (16) //in bytes
#define AES_192_KEYSIZE (24) //in bytes
#define AES_256_KEYSIZE (32) //in bytes

#define AES_INSTRCTIONS_CPUID_BIT (1<<25)

static void iaesni_cpuid(unsigned int res[4], int leaf){
#ifdef _WIN32
    __cpuid((int *)res, leaf);
#else
    __cpuid(leaf, res[0], res[1], res[2], res[3]);
#endif
}

/* 
 * check_for_aes_instructions()
 *   return 1 if cpu supports AES-NI, 0 otherwise
 */

int check_for_aes_instructions(void) {/*eax|ebx|ecx|edx*/
    unsigned int cpuid_results[4] = {0, 0, 0, 0};
    /* leaf 0 returns vendor string */
    iaesni_cpuid(cpuid_results, 0);
    /*
     *      MSB         LSB
     * EBX = 'u' 'n' 'e' 'G'
     * EDX = 'I' 'e' 'n' 'i'
     * ECX = 'l' 'e' 't' 'n'
     */

    /* swap 2 and 3 register values to make them appear as EBX EDX ECX */
    {
        unsigned temp = cpuid_results[2];
        cpuid_results[2] = cpuid_results[3];
        cpuid_results[3] = temp;
    }

    if (cpuid_results[0] < 1) {
        return 0;
    }
    /* check cpu vendor */
    if (memcmp(&cpuid_results[1], "GenuineIntel", sizeof(*cpuid_results) * 3) != 0 && memcmp(&cpuid_results[1], "AuthenticAMD", sizeof(*cpuid_results) * 3) != 0) {
        return 0;
    }

    /* leaf 1 returns cpu info, ecx contains feature flag we're interested in */
    iaesni_cpuid(cpuid_results, 1);

    if (cpuid_results[2] & AES_INSTRCTIONS_CPUID_BIT) {
        return 1;
    }

	return 0;
}

void intel_AES_enc128(const UCHAR *plainText,UCHAR *cipherText,const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey128(key,expandedKey);
	iEnc128(&aesData);
}

void intel_AES_enc128_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CBC(&aesData);
}


void intel_AES_enc192(const UCHAR *plainText,UCHAR *cipherText,const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey192(key,expandedKey);
	iEnc192(&aesData);
}

void intel_AES_enc192_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CBC(&aesData);
}


void intel_AES_enc256(const UCHAR *plainText,UCHAR *cipherText,const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey256(key,expandedKey);
	iEnc256(&aesData);
}

void intel_AES_enc256_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CBC(&aesData);
}

void intel_AES_dec128(const UCHAR *cipherText,UCHAR *plainText,const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey128(key,expandedKey);
	iDec128(&aesData);
}

void intel_AES_dec128_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey128(key,expandedKey);
	iDec128_CBC(&aesData);
}


void intel_AES_dec192(const UCHAR *cipherText,UCHAR *plainText,const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey192(key,expandedKey);
	iDec192(&aesData);
}

void intel_AES_dec192_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey192(key,expandedKey);
	iDec192_CBC(&aesData);
}


void intel_AES_dec256(const UCHAR *cipherText,UCHAR *plainText, const UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey256(key,expandedKey);
	iDec256(&aesData);
}

void intel_AES_dec256_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey256(key,expandedKey);
	iDec256_CBC(&aesData);
}

void intel_AES_encdec256_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, const UCHAR *initial_counter, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = input;
	aesData.out_block = output;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = initial_counter;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CTR(&aesData);
}

void intel_AES_encdec192_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, const UCHAR *initial_counter, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = input;
	aesData.out_block = output;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = initial_counter;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CTR(&aesData);
}

void intel_AES_encdec128_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, const UCHAR *initial_counter, size_t numBlocks) {
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = input;
	aesData.out_block = output;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = initial_counter;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CTR(&aesData);
}


int enc_128_CBC(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_iv[i] = iv[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_enc128_CBC(plaintext, ct, _key, _iv, numBlocks);
	return 0;
}


int dec_128_CBC(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *iv, int numBlocks){
	
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;
	
	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);
	
	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_iv[i] = iv[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_dec128_CBC(ciphertext, pt, _key, _iv, numBlocks);
	return 0;
}


int enc_192_CBC(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}
	
	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_enc192_CBC(plaintext, ct, _key, _iv, numBlocks);

	return 0;

}

int dec_192_CBC(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *iv, int numBlocks){

	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_dec192_CBC(ciphertext, pt, _key, _iv, numBlocks);
	return 0;
}


int enc_256_CBC(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *iv, int numBlocks)
{
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}
	
	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_enc256_CBC(plaintext, ct, _key, _iv, numBlocks);
	return 0;
}


int dec_256_CBC(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *iv, int numBlocks){
	
	unsigned int buffer_size =  numBlocks * BLOCK_SIZE;
	unsigned int i;
	
	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _iv[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);
	
	for (i=0;i<BLOCK_SIZE;i++)
	{
		_iv[i] = iv[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_dec256_CBC(ciphertext, pt, _key, _iv, numBlocks);
	return 0;
}

int enc_128_CTR(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}
	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_encdec128_CTR(plaintext, ct, _key, _ic, numBlocks);
	
	return 0;
}


int dec_128_CTR(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_128_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_encdec128_CTR(ciphertext, pt, _key, _ic, numBlocks);

	return 0;
}

int enc_192_CTR(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_encdec192_CTR(plaintext, ct, _key, _ic, numBlocks);

	return 0;
}

int dec_192_CTR(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_192_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_key[i] = key[i];
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_192_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_encdec192_CTR(ciphertext, pt, _key, _ic, numBlocks);

	return 0;
}


int enc_256_CTR(const UCHAR *pt, UCHAR *ct, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *plaintext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		plaintext[i] = pt[i];
	}

    intel_AES_encdec256_CTR(plaintext, ct, _key, _ic, numBlocks);

	return 0;
}

int dec_256_CTR(const UCHAR *ct, UCHAR *pt, const UCHAR *key, const UCHAR *ic, int numBlocks)
{
	unsigned int buffer_size = numBlocks*BLOCK_SIZE;
	unsigned int i;

	UCHAR _key[AES_256_KEYSIZE];
	UCHAR _ic[BLOCK_SIZE];
	UCHAR *ciphertext = (UCHAR*)_alloca(buffer_size);

	for (i=0;i<BLOCK_SIZE;i++)
	{
		_ic[i] = ic[i];
	}

	for (i=0;i<AES_256_KEYSIZE;i++)
	{
		_key[i] = key[i];
	}

	for (i=0;i<buffer_size;i++)
	{
		ciphertext[i] = ct[i];
	}

    intel_AES_encdec256_CTR(ciphertext, pt, _key, _ic, numBlocks);

	return 0;
}
