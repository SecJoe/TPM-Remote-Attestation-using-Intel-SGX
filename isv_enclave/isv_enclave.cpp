/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//TODO: Describe all function with parameters detailed.


#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define BOOLEAN_TPM_VERIFY_STATE 1
#define SAMPLE_SP_TAG_SIZE          16
#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


//check first if the public matches the requirements (secp256r1 ECC curve).
//After that I check if the TPM siganature is valid.
sgx_status_t verify_ecdsa_signature(
    sgx_ec256_public_t *public_key,
    uint8_t *attest_data,
    uint32_t attest_data_size,
    sgx_ec256_signature_t *signature)
{

	sgx_ecc_state_handle_t handle;
	sgx_status_t ret;
	uint8_t verify_signature_result;
	int *p_check_point_valid = (int *) malloc(sizeof(int));


	ret = sgx_ecc256_open_context(&handle);
    if(ret != SGX_SUCCESS)
	{
		PrintError("sgx_ecc256_open_context - status error.");
        return ret;
	}

	ret = sgx_ecc256_check_point(public_key, handle, p_check_point_valid);
	if(ret != SGX_SUCCESS){
   		PrintError("sgx_ecc256_check_point error - this should never happen.");
   		return ret;
	}else if(*p_check_point_valid == 0){
  		PrintError("The public key is not on the correct curve. The public key needs to match the requirements secp256r1 (NIST P-256)\n");
  		return SGX_ERROR_UNEXPECTED;
	}

	ret = sgx_ecdsa_verify(attest_data, attest_data_size, public_key, signature, &verify_signature_result, handle);
	if(ret != SGX_SUCCESS){
   		PrintError("sgx_ecdsa_verify - this should never happen.");
   		return ret;
	}else if(verify_signature_result != SGX_EC_VALID){
		PrintError("TPM signature invalid\n");
		return SGX_ERROR_INVALID_SIGNATURE;
	}else{
  		return SGX_SUCCESS;
 	}
}

//check if the TPM PCRs are valid. I check (compare) against the hardcoded value: 0x00.
//I hash this value before, because the PCRs are also a hash of values.
//further you can add more PCRs here, because configuring the PCRs via ECall
//from the untrusted code can lacerate a security hole.
sgx_status_t check_pcr(
    uint8_t *attest_data,
	uint32_t attest_data_size,
    uint32_t pcr_size)
{

	sgx_status_t status;
	uint8_t *pcr_digest = &attest_data[81];

	sgx_sha256_hash_t *p_hash = (sgx_sha256_hash_t *) malloc(sizeof(sgx_sha256_hash_t));
	uint8_t *p_source = (uint8_t *) malloc(sizeof(uint8_t));

	for(int i = 0; i<pcr_size; i++){
		p_source[i] = 0x00;
	}

	status = sgx_sha256_msg(p_source, pcr_size, p_hash);

	if(consttime_memequal(*p_hash, pcr_digest, 32) == 1){
		return SGX_SUCCESS;
	}

	return SGX_ERROR_UNEXPECTED;
}

sgx_status_t secure_verify(
    sgx_ra_context_t context,
    tpm_enc_att_state_request_message_t *encrypted_req_message,
    uint32_t request_msg_size,
	sgx_ec256_public_t *tpm_public_key,
    uint8_t *tpm_attest_data,
    uint32_t tpm_attest_data_size,
    sgx_ec256_signature_t *tpm_signature,
	uint32_t tpm_pcr_size, //TODO not needed, always the sem size?
	tpm_enc_att_state_response_message_t *p_ver_msg_out,
	uint32_t ver_msg_size)
{


    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
	
	//request messages inits
	tpm_unenc_att_state_request_message_t *unencrypted_req_message = (tpm_unenc_att_state_request_message_t *) malloc(sizeof(tpm_unenc_att_state_request_message_t));

	//response messages inits
	tpm_unenc_att_state_response_message_t *unencrypted_resp_msg = (tpm_unenc_att_state_response_message_t*) malloc(sizeof(tpm_unenc_att_state_response_message_t));
	
	

	//TODO: ver_msg_size = field size needed for edl, alternative?

	//Pre checks
	if(encrypted_req_message == NULL)
	{
		PrintError("secure_verify: encrypted_req_message is NULL");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	if(tpm_public_key == NULL)
	{
		PrintError("secure_verify: tpm_public_key is NULL");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	if(tpm_attest_data == NULL)
	{
		PrintError("secure_verify: tpm_attest_data is NULL");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	if(tpm_signature == NULL)
	{
		PrintError("secure_verify: tpm_signaure is NULL");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	if(p_ver_msg_out == NULL)
	{
		PrintError("secure_verify: p_ver_msg_out is NULL");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	//Check correct sizes
	//TODO: delete check? 
	if(request_msg_size != 129)
	{
		PrintError("secure_verify: Wrong request_msg_size. In this confguration messages_size should be 129 bytes.");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	if(ver_msg_size == sizeof(tpm_unenc_att_state_response_message_t)){
		PrintError("secure_verify: Wrong ver_msg_size. In this confguration ver_size should be == sizeof(tpm_unenc_att_state_response_message_t)");
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}


	//!!!!!!Checks done, beginning of the computation-block

	//Obtain key to decrypt the message from the service-Provider. key was negotiated bafore with SIGMA-like protocol.
	ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
	if(SGX_SUCCESS != ret)
	{
		PrintError("secure_verify: Can not obtain decryption key in enclave.");
		return ret;
	}

	//Decrypt message from service provider (SP) and save it in unencrypted_req_message->platform_info_blob.
	//AES-GCM provides authenticity (message is from SP), confidentiality (message is encrypted),
	//Integrity and freshness (if the SP provides unique Nonces in every message. My SP provides this).
	ret = sgx_rijndael128GCM_decrypt(&sk_key,
									(uint8_t *) encrypted_req_message,
									sizeof(ias_platform_info_blob_t),
									(uint8_t *) &unencrypted_req_message->platform_info_blob,
									&encrypted_req_message->nonce.nonce[0],
									encrypted_req_message->nonce.nonce_size,
									NULL,
									0,
									&encrypted_req_message->mac);

	//Check on some errors while decryption.
	if(ret == SGX_ERROR_MAC_MISMATCH){
		PrintError("secure_verify: enclave request decrypt: mac missmatch\n");
	}else if(ret == SGX_ERROR_INVALID_PARAMETER){
		PrintError("secure_verify: enclave request decrypt: invalid parameter\n");
	}else if(ret == SGX_ERROR_OUT_OF_MEMORY){
		PrintError("secure_verify: enclave request decrypt: out of memory\n");
	}else if(ret == SGX_ERROR_UNEXPECTED){	
		PrintError("secure_verify: enclave request decrypt: unexcepted error - sgx internal error\n");
	}else if(ret == SGX_SUCCESS){
		//PrintError("secure_verify: enclave request decrypt: SUCCESS\n");
	}else{
		PrintError("secure_verify: enclave request decrypt: Fatal Error - Undocumented Error!?\n");
		return ret;
	}	


	//!!!!!Start TPM Quote validation
	
	//Check if the curve is correct and if the signature is valid (more information see implemention of this method above)
	ret = verify_ecdsa_signature(tpm_public_key, tpm_attest_data, tpm_attest_data_size, tpm_signature);

	if (ret == SGX_SUCCESS) {
		//check if PCRs are correct (more information see implemention of this method above)
		ret = check_pcr(tpm_attest_data, tpm_attest_data_size, tpm_pcr_size);
	}

	if(ret == SGX_SUCCESS){
		unencrypted_resp_msg->tpm_platform_info_blob.tpm_verify_status[0] = 0xEF; //tpm attestation successful.
	}else{
		unencrypted_resp_msg->tpm_platform_info_blob.tpm_verify_status[0] = 0x00; //tpm attestation not successful.
	}
	
	//equip response message with Nonce and size of Nonce
	memcpy(&p_ver_msg_out->nonce.nonce[0], &encrypted_req_message->nonce.nonce[0], AES_GCM_IV_SIZE);
	p_ver_msg_out->nonce.nonce_size = encrypted_req_message->nonce.nonce_size;

				//encrypt tpm attest message with nonce and save mac additionally
				ret = sgx_rijndael128GCM_encrypt(&sk_key, (uint8_t *) unencrypted_resp_msg, sizeof(tpm_unenc_att_state_response_message_t),  &p_ver_msg_out->ciphertext[0], &p_ver_msg_out->nonce.nonce[0], p_ver_msg_out->nonce.nonce_size, NULL, 0, &p_ver_msg_out->mac);

				//TODO: Debugging of enclave operations is a security problem. Delete it in release mode.
				PrintError("Debug: Enclave Cipher: \n");
				PrintError_array(&p_ver_msg_out->ciphertext[0]);

				PrintError("Debug: Enclave IV: \n");
				PrintError_array(&p_ver_msg_out->nonce.nonce[0]);

				PrintError("Debug: Enclave Key: \n");
				PrintError_array(&sk_key[0]);

				PrintError("Debug: Enclave MAC: \n");
				PrintError_array(&p_ver_msg_out->mac[0]);
				
				if(ret == SGX_ERROR_INVALID_PARAMETER){
					PrintError("secure_verify: enclave response encrypt: invalid parameter\n");
				}else if(ret == SGX_ERROR_OUT_OF_MEMORY){
					PrintError("secure_verify: enclave response encrypt: out of memory\n");
				}else if(ret == SGX_ERROR_UNEXPECTED){	
					PrintError("secure_verify: enclave response encrypt: unexcepted error - sgx internal error\n");
				}else if(ret == SGX_SUCCESS){
					//PrintError("secure_verify: enclave request decrypt: SUCCESS\n");
					return ret;
				}else{
					PrintError("secure_verify: enclave request decrypt: Fatal Error - Undocumented Error!?\n");
					return ret;
				}	

    return ret;
}
