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

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server.



#include <stdio.h>
#include <limits.h>
#include <unistd.h>
// Needed for definition of remote attestation messages.

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"


#define ENCLAVE_PATH "isv_enclave.signed.so"

//debug TPM Attestation events
#define EXTENDED_DEBUG       1

#define SWAP_ENDIAN_DW(dw)    ((((dw) & 0x000000ff) << 24)                  \
    | (((dw) & 0x0000ff00) << 8)                                            \
    | (((dw) & 0x00ff0000) >> 8)                                            \
| (((dw) & 0xff000000) >> 24))

#define SWAP_ENDIAN_32B(ptr)                                                \
{                                                                           \
    unsigned int temp = 0;                                                  \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[0]);                       \
    ((unsigned int*)(ptr))[0] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[7]);  \
    ((unsigned int*)(ptr))[7] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[1]);                       \
    ((unsigned int*)(ptr))[1] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[6]);  \
    ((unsigned int*)(ptr))[6] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[2]);                       \
    ((unsigned int*)(ptr))[2] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[5]);  \
    ((unsigned int*)(ptr))[5] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[3]);                       \
    ((unsigned int*)(ptr))[3] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[4]);  \
    ((unsigned int*)(ptr))[4] = temp;                                       \
}

#define TPM_PUBKEY_FILE "/home/sgx/Schreibtisch/TSS/utils/pubkey.txt"
#define TPM_ATTEST_FILE "/home/sgx/Schreibtisch/TSS/utils/attest"
#define TPM_SIGNATURE_FILE "/home/sgx/Schreibtisch/TSS/utils/attestsig"

uint8_t* msg1_samples[] = { msg1_sample1, msg1_sample2 };
uint8_t* msg2_samples[] = { msg2_sample1, msg2_sample2 };
uint8_t* msg3_samples[MSG3_BODY_SIZE] = { msg3_sample1, msg3_sample2 };
uint8_t* attestation_msg_samples[] =
    { attestation_msg_sample1, attestation_msg_sample2};

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len) {
	if (!mem || !len) {
		fprintf(file, "\n( null )\n");
		return;
	}
	uint8_t *array = (uint8_t *) mem;
	fprintf(file, "%u bytes:\n{\n", len);
	uint32_t i = 0;
	for (i = 0; i < len - 1; i++) {
		fprintf(file, "0x%x, ", array[i]);
		if (i % 8 == 7)
			fprintf(file, "\n");
	}
	fprintf(file, "0x%x ", array[i]);
	fprintf(file, "\n}\n");
}

//Debugging function. Print the response from the attestation service.
void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file,
		ra_samp_response_header_t *response) {
	if (!response) {
		fprintf(file, "\t\n( null )\n");
		return;
	}

	fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
	fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
			response->status[1]);
	fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

	if (response->type == TYPE_RA_MSG2) {
		sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*) (response->body);

		fprintf(file, "MSG2 gb - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

		fprintf(file, "MSG2 spid - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

		fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

		fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

		fprintf(file, "MSG2 sign_gb_ga - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
				sizeof(p_msg2_body->sign_gb_ga));

		fprintf(file, "MSG2 mac - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

		fprintf(file, "MSG2 sig_rl - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
				p_msg2_body->sig_rl_size);
	} else if (response->type == TYPE_RA_TPM_ATT_REQUEST) {
		sample_ra_att_result_msg_t *p_att_result =
				(sample_ra_att_result_msg_t *) (response->body);
		fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
		PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
				sizeof(p_att_result->platform_info_blob));

		fprintf(file, "ATTESTATION RESULT MSG mac - ");
		PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

		fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
				p_att_result->secret.payload_size);

		fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
		PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
				p_att_result->secret.payload_size);
	} else {
		fprintf(file, "\nERROR in printing out the response. "
				"Response of type not supported %d\n", response->type);
	}
}

/* This method is multiple times needed to read a file in the memory
*	@params filename: the file to read.
* @param OutfileSize: The number of bytes readed from that file (output).
*/
void* readFileInMemory(const char *filename, long* OutfileSize) {
	void *data;
	FILE *file;

	file = fopen(filename, "rb");
	if (file == NULL) {
		printf("Cant open file. Maybe path incorrect?\n");
	}

	fseek(file, 0, SEEK_END);
	*OutfileSize = ftell(file);
	if (OutfileSize <= 0) {
		printf("File too small. Please check file\n");
	}

	fseek(file, 0, SEEK_SET);
	data = malloc(*OutfileSize + 1);
	fread(data, *OutfileSize, 1, file);
	fclose(file);
	return data;
}

/*Check header of tpm publicArea. Only SHA-256 as digit and ECDSA with curve secp256r1(nist p256) is supported.
 Also the PCR values should be hashed with SHA-256 */
int checkPublicArea(uint8_t* data) {
	if (data[1] != 0x58) {
		printf("PublicArea size not 88\n");
		return EXIT_FAILURE;
	} else if (data[3] != 0x23) { //TPM_ALG_ECC
		printf(
				"SGX only supports ECC verification. Please use ECC and not RSA etc.\n");
		return EXIT_FAILURE;
	} else if (data[5] != 0x0b) { //TPM_ALG_SHA256 (attest data must be hashed with sha256
		printf("attest data  not hashed with SHA256!\n");
		return EXIT_FAILURE;
	} else if (data[19] != 0x03) { //TPM_ECC_NIST_P256
		printf("Wrong ECC Curve, TPM_ECC_NIST_P256 (secp256r1) needed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/*Bridge/Proxy enclave>untrusted-app. Print enclave errors for simpler debugging*/
void PrintError(const char *str) {
	printf("Enclave Error: %s", str);
}

/*Bridge/Proxy enclave>untrusted-app. Print full enclave arrays for simpler debugging*/
void PrintError_array(uint8_t *array) {
	FILE* OUTPUT = stdout;
	PRINT_BYTE_ARRAY(OUTPUT, array, 133);
}

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x
int main(int argc, char* argv[]) {
	int ret = 0;
	ra_samp_request_header_t *p_msg0_full = NULL;
	ra_samp_response_header_t *p_msg0_resp_full = NULL;
	ra_samp_request_header_t *p_msg1_full = NULL;
	ra_samp_response_header_t *p_msg2_full = NULL;
	sgx_ra_msg3_t *p_msg3 = NULL;
	ra_samp_response_header_t* p_att_result_msg_full = NULL;
	ra_samp_response_header_t* p_tpm_attest_result_message = NULL; //not needed actually. this is only needed to avoid a null pointer error
	sgx_enclave_id_t enclave_id = 0;
	int enclave_lost_retry_time = 1;
	int busy_retry_time = 4;
	sgx_ra_context_t context = INT_MAX;
	sgx_status_t status = SGX_SUCCESS;
	ra_samp_request_header_t* p_msg3_full = NULL;
	ra_samp_request_header_t* p_ver_msg_full = NULL;

	int32_t verify_index = -1;
	int32_t verification_samples = sizeof(msg1_samples)
			/ sizeof(msg1_samples[0]);

	FILE* OUTPUT = stdout;

#define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && \
                                       verify_index <= verification_samples)
#define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

	if (argc > 1) {

		verify_index = atoi(argv[1]);

		if ( VERIFICATION_INDEX_IS_VALID()) {
			fprintf(OUTPUT, "\nVerifying precomputed attestation messages "
					"using precomputed values# %d\n", verify_index);
		} else {
			fprintf(OUTPUT, "\nValid invocations are:\n");
			fprintf(OUTPUT, "\n\tisv_app\n");
			fprintf(OUTPUT, "\n\tisv_app <verification index>\n");
			fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
					verification_samples);
			fprintf(OUTPUT, "\nUsing a verification index uses precomputed "
					"messages to assist debugging the remote attestation "
					"service provider.\n");
			return -1;
		}
	}

	// Preparation for remote attestation by configuring extended epid group id.
	{
		uint32_t extended_epid_group_id = 0;
		ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
		if (SGX_SUCCESS != ret) {
			ret = -1;
			fprintf(OUTPUT,
					"\nError, call sgx_get_extended_epid_group_id fail [%s].",
					__FUNCTION__);
			return ret;
		}
		fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

		p_msg0_full = (ra_samp_request_header_t*) malloc(
				sizeof(ra_samp_request_header_t) + sizeof(uint32_t));
		if (NULL == p_msg0_full) {
			ret = -1;
			goto CLEANUP;
		}
		p_msg0_full->type = TYPE_RA_MSG0;
		p_msg0_full->size = sizeof(uint32_t);

		*(uint32_t*) ((uint8_t*) p_msg0_full + sizeof(ra_samp_request_header_t)) =
				extended_epid_group_id;
		{

			fprintf(OUTPUT, "\nMSG0 body generated -\n");

			PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

		}
		// The ISV application sends msg0 to the SP.
		// The ISV decides whether to support this extended epid group id.
		fprintf(OUTPUT,
				"\nSending msg0 to remote attestation service provider.\n");

		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
				p_msg0_full, &p_msg0_resp_full);
		if (ret != 0) {
			fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
					"[%s].", __FUNCTION__);
			goto CLEANUP;
		}
		fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");
	}
	// Remote attestation will be initiated the ISV server challenges the ISV
	// app or if the ISV app detects it doesn't have the credentials
	// (shared secret) from a previous attestation required for secure
	// communication with the server.
	{
		// ISV application creates the ISV enclave.
		int launch_token_update = 0;
		sgx_launch_token_t launch_token = { 0 };
		memset(&launch_token, 0, sizeof(sgx_launch_token_t));
		do {
			ret = sgx_create_enclave(_T(ENCLAVE_PATH), SGX_DEBUG_FLAG,
					&launch_token, &launch_token_update, &enclave_id, NULL);
			if (SGX_SUCCESS != ret) {
				ret = -1;
				fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
						__FUNCTION__);
				goto CLEANUP;
			}
			fprintf(OUTPUT, "\nCall sgx_create_enclave success.");

			ret = enclave_init_ra(enclave_id, &status, false, &context);
			//Ideally, this check would be around the full attestation flow.
		} while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

		if (SGX_SUCCESS != ret || status) {
			ret = -1;
			fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
					__FUNCTION__);
			goto CLEANUP;
		}
		fprintf(OUTPUT, "\nCall enclave_init_ra success.");

		// isv application call uke sgx_ra_get_msg1
		p_msg1_full = (ra_samp_request_header_t*) malloc(
				sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t));
		if (NULL == p_msg1_full) {
			ret = -1;
			goto CLEANUP;
		}
		p_msg1_full->type = TYPE_RA_MSG1;
		p_msg1_full->size = sizeof(sgx_ra_msg1_t);
		do {
			ret = sgx_ra_get_msg1(context, enclave_id, sgx_ra_get_ga,
					(sgx_ra_msg1_t*) ((uint8_t*) p_msg1_full
							+ sizeof(ra_samp_request_header_t)));
			sleep(3); // Wait 3s between retries
		} while (SGX_ERROR_BUSY == ret && busy_retry_time--);
		if (SGX_SUCCESS != ret) {
			ret = -1;
			fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
					__FUNCTION__);
			goto CLEANUP;
		} else {
			fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

			fprintf(OUTPUT, "\nMSG1 body generated -\n");

			PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

		}

		if (VERIFICATION_INDEX_IS_VALID()) {
			memcpy_s(p_msg1_full->body, p_msg1_full->size,
					msg1_samples[GET_VERIFICATION_ARRAY_INDEX()],
					p_msg1_full->size);

			fprintf(OUTPUT, "\nInstead of using the recently generated MSG1, "
					"we will use the following precomputed MSG1 -\n");

			PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
		}

		// The ISV application sends msg1 to the SP to get msg2,
		// msg2 needs to be freed when no longer needed.
		// The ISV decides whether to use linkable or unlinkable signatures.
		fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider."
				"Expecting msg2 back.\n");

		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
				p_msg1_full, &p_msg2_full);

		if (ret != 0 || !p_msg2_full) {
			fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
					"[%s].", __FUNCTION__);
			if (VERIFICATION_INDEX_IS_VALID()) {
				fprintf(OUTPUT, "\nBecause we are in verification mode we will "
						"ignore this error.\n");
				fprintf(OUTPUT, "\nInstead, we will pretend we received the "
						"following MSG2 - \n");

				SAFE_FREE(p_msg2_full);
				ra_samp_response_header_t* precomputed_msg2 =
						(ra_samp_response_header_t*) msg2_samples[
						GET_VERIFICATION_ARRAY_INDEX()];
				const size_t msg2_full_size = sizeof(ra_samp_response_header_t)
						+ precomputed_msg2->size;
				p_msg2_full = (ra_samp_response_header_t*) malloc(
						msg2_full_size);
				if (NULL == p_msg2_full) {
					ret = -1;
					goto CLEANUP;
				}
				memcpy_s(p_msg2_full, msg2_full_size, precomputed_msg2,
						msg2_full_size);

				PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
						sizeof(ra_samp_response_header_t) + p_msg2_full->size);
			} else {
				goto CLEANUP;
			}
		} else {
			// Successfully sent msg1 and received a msg2 back.
			// Time now to check msg2.
			if (TYPE_RA_MSG2 != p_msg2_full->type) {

				fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
						"[%s].", __FUNCTION__);

				if (VERIFICATION_INDEX_IS_VALID()) {
					fprintf(OUTPUT, "\nBecause we are in verification mode we "
							"will ignore this error.");
				} else {
					goto CLEANUP;
				}
			}

			fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
					"provider. Received the following MSG2:\n");
			PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
					sizeof(ra_samp_response_header_t) + p_msg2_full->size);

			fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
			PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

			if ( VERIFICATION_INDEX_IS_VALID()) {
				// The response should match the precomputed MSG2:
				ra_samp_response_header_t* precomputed_msg2 =
						(ra_samp_response_header_t *) msg2_samples[GET_VERIFICATION_ARRAY_INDEX()];
				if (memcmp(precomputed_msg2, p_msg2_full,
						sizeof(ra_samp_response_header_t)
								+ p_msg2_full->size)) {
					fprintf(OUTPUT, "\nVerification ERROR. Our precomputed "
							"value for MSG2 does NOT match.\n");
					fprintf(OUTPUT, "\nPrecomputed value for MSG2:\n");
					PRINT_BYTE_ARRAY(OUTPUT, precomputed_msg2,
							sizeof(ra_samp_response_header_t)
									+ precomputed_msg2->size);
					fprintf(OUTPUT, "\nA more descriptive representation "
							"of precomputed value for MSG2:\n");
					PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT,
							precomputed_msg2);
				} else {
					fprintf(OUTPUT, "\nVerification COMPLETE. Remote "
							"attestation service provider generated a "
							"matching MSG2.\n");
				}
			}

		}

		sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*) ((uint8_t*) p_msg2_full
				+ sizeof(ra_samp_response_header_t));

		uint32_t msg3_size = 0;
		if ( VERIFICATION_INDEX_IS_VALID()) {
			// We cannot generate a valid MSG3 using the precomputed messages
			// we have been using. We will use the precomputed msg3 instead.
			msg3_size = MSG3_BODY_SIZE;
			p_msg3 = (sgx_ra_msg3_t*) malloc(msg3_size);
			if (NULL == p_msg3) {
				ret = -1;
				goto CLEANUP;
			}
			memcpy_s(p_msg3, msg3_size,
					msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
			fprintf(OUTPUT, "\nBecause MSG1 was a precomputed value, the MSG3 "
					"we use will also be. PRECOMPUTED MSG3 - \n");
		} else {
			busy_retry_time = 2;
			// The ISV app now calls uKE sgx_ra_proc_msg2,
			// The ISV app is responsible for freeing the returned p_msg3!!
			do {
				ret = sgx_ra_proc_msg2(context, enclave_id,
						sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
						p_msg2_body, p_msg2_full->size, &p_msg3, &msg3_size);
			} while (SGX_ERROR_BUSY == ret && busy_retry_time--);
			if (!p_msg3) {
				fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
						"p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
				ret = -1;
				goto CLEANUP;
			}
			if (SGX_SUCCESS != (sgx_status_t) ret) {
				fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
						"ret = 0x%08x [%s].", ret, __FUNCTION__);
				ret = -1;
				goto CLEANUP;
			} else {
				fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
				fprintf(OUTPUT, "\nMSG3 - \n");
			}
		}

		PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

		p_msg3_full = (ra_samp_request_header_t*) malloc(
				sizeof(ra_samp_request_header_t) + msg3_size);
		if (NULL == p_msg3_full) {
			ret = -1;
			goto CLEANUP;
		}
		p_msg3_full->type = TYPE_RA_MSG3;
		p_msg3_full->size = msg3_size;
		if (memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size)) {
			fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s].",
					__FUNCTION__);
			ret = -1;
			goto CLEANUP;
		}

		// The ISV application sends msg3 to the SP to get the attestation
		// result message, attestation result message needs to be freed when
		// no longer needed. The ISV service provider decides whether to use
		// linkable or unlinkable signatures. The format of the attestation
		// result is up to the service provider. This format is used for
		// demonstration.  Note that the attestation result message makes use
		// of both the MK for the MAC and the SK for the secret. These keys are
		// established from the SIGMA secure channel binding.
		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
				p_msg3_full, &p_att_result_msg_full);
		if (ret || !p_att_result_msg_full) {
			ret = -1;
			fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
			goto CLEANUP;
		}

		tpm_enc_att_state_request_message_t * p_att_result_msg_body =
				(tpm_enc_att_state_request_message_t *) ((uint8_t*) p_att_result_msg_full
						+ sizeof(ra_samp_response_header_t));
		if (TYPE_RA_TPM_ATT_REQUEST != p_att_result_msg_full->type) {
			ret = -1;
			fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
					"received was NOT of type att_msg_result. Type = "
					"%d. [%s].", p_att_result_msg_full->type, __FUNCTION__);
			goto CLEANUP;
		} else {
			fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation "
					"result message back\n.");
			if ( VERIFICATION_INDEX_IS_VALID()) {
				if (memcmp(p_att_result_msg_full->body,
						attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
						p_att_result_msg_full->size)) {
					fprintf(OUTPUT, "\nSent MSG3 successfully. Received an "
							"attestation result message back that did "
							"NOT match the expected value.\n");
					fprintf(OUTPUT, "\nEXPECTED ATTESTATION RESULT -");
					PRINT_BYTE_ARRAY(OUTPUT,
							attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
							p_att_result_msg_full->size);
				}
			}
		}

		fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
		PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
				p_att_result_msg_full->size);

		if ( VERIFICATION_INDEX_IS_VALID()) {
			fprintf(OUTPUT, "\nBecause we used precomputed values for the "
					"messages, the attestation result message will "
					"not pass further verification tests, so we will "
					"skip them.\n");
			goto CLEANUP;
		}

		bool attestation_passed = true;
		// Check the attestation result for pass or fail.
		// Whether attestation passes or fails is a decision made by the ISV Server.
		// When the ISV server decides to trust the enclave, then it will return success.
		// When the ISV server decided to not trust the enclave, then it will return failure.
		if (0 != p_att_result_msg_full->status[0]
				|| 0 != p_att_result_msg_full->status[1]) {
			fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
					"failed in [%s].", __FUNCTION__);
			attestation_passed = false;
		}

		// The attestation result message should contain a field for the Platform
		// Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
		// It is not returned in all cases, but when it is, the ISV app
		// should pass it to the blob analysis API called sgx_report_attestation_status()
		// along with the trust decision from the ISV server.
		// The ISV application will take action based on the update_info.
		// returned in update_info by the API.
		// This call is stubbed out for the sample.
		//
		// sgx_update_info_bit_t update_info;
		// ret = sgx_report_attestation_status(
		//     &p_att_result_msg_body->platform_info_blob,
		//     attestation_passed ? 0 : 1, &update_info);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		//PUBLIC-KEY////////////////////////////////////////////
		sgx_ec256_public_t *public_key_be = (sgx_ec256_public_t *) malloc(sizeof(sgx_ec256_public_t));
		sgx_ec256_public_t *public_key = (sgx_ec256_public_t *) malloc(sizeof(sgx_ec256_public_t)); //public key in big endian format from TPM
		sgx_ec256_signature_t *signature_be = (sgx_ec256_signature_t *) malloc(sizeof(sgx_ec256_signature_t));
		sgx_ec256_signature_t *signature = (sgx_ec256_signature_t *) malloc(sizeof(sgx_ec256_signature_t));
		uint8_t *attest_file = (uint8_t *) malloc(113); //The attest file has usually a size of 113 Byte. (see TSS 2.0 Specs).
		uint8_t *pk_file = (uint8_t *) malloc(90); //The sublic key file has usually a size of 90 Byte (22 byte Header+ (2*32+2 bytes pk.gx, pk.gy + size). (see TSS 2.0 Specs).
		uint8_t *sig_file = (uint8_t *) malloc(72); //The signature file has usually a size of 72 Byte (see TSS 2.0 Specs).
		uint8_t *sig_file_x = (uint8_t *) malloc(32); //The X structure of the signanture has usually a size of 32 Byte (see TSS 2.0 Specs)
		uint8_t *sig_file_y = (uint8_t *) malloc(32); //The Y structure of the signanture has usually a size of 32 Byte (see TSS 2.0 Specs)
		uint32_t attest_size;

		long fileSize = 0;
		pk_file = (uint8_t *) readFileInMemory(TPM_PUBKEY_FILE, &fileSize);

		/*check public Area header. Print errors and SGX_FAILURE on failure or throw EXIT_SUCCESS on success. */
		if (checkPublicArea(pk_file) != EXIT_SUCCESS) {
			goto CLEANUP;
		}

		pk_file = &pk_file[22]; //jump over header, see method above.

		memcpy(&public_key_be->gx, &pk_file[2], (int) pk_file[1]); //FileSize of x (usually 32 byte) is dfined in second Byte[1] (first Byte [0] only for sizes higher than 255), data begin at third byte [2]
		memcpy(&public_key_be->gy, &pk_file[(int) pk_file[1] + 4],
				(int) pk_file[(int) pk_file[1] + 3]); //databegin of y: size from x + 4 (2*2 size byte), length in second byte after x blob (see above)

		//convert TPM Public_key-X big endian format to little endian (needed by sgx).
		fileSize = (int) pk_file[1];
		uint8_t *pFromX = (public_key_be->gx + (fileSize - 1));
		uint8_t *pToX = public_key->gx;
		for (; fileSize != 0; fileSize--)
			*pToX++ = *pFromX--;

		//convert TPM Public_key-Y big endian format to little endian (needed by sgx).
		fileSize = (int) pk_file[(int) pk_file[1] + 3];
		uint8_t *pFromY = (public_key_be->gy + (fileSize - 1));
		uint8_t *pToY = public_key->gy;
		for (; fileSize != 0; fileSize--)
			*pToY++ = *pFromY--;

		if (EXTENDED_DEBUG) {
			fprintf(OUTPUT, "\npublic_key->gx - \n");
			PRINT_BYTE_ARRAY(OUTPUT, &(public_key->gx), sizeof(public_key->gx));
			fprintf(OUTPUT, "\npublic_key->gy - \n");
			PRINT_BYTE_ARRAY(OUTPUT, &(public_key->gy), sizeof(public_key->gy));
		}

		//ATTEST-DATA////////////////////////////////////////////
		attest_file = (uint8_t *) readFileInMemory(TPM_ATTEST_FILE, &fileSize);
		attest_size = 113;

		if (EXTENDED_DEBUG) {
			fprintf(OUTPUT, "\nattest_file - \n");
			PRINT_BYTE_ARRAY(OUTPUT, &(attest_file), attest_size);
		}

		//SIGNATURE!!////////////////////////////////////////////
		fileSize = 0;
		sig_file = (uint8_t *) readFileInMemory(TPM_SIGNATURE_FILE, &fileSize);

		sig_file = &sig_file[4]; //jump over header (4 Bytes)

		memcpy(signature->x, &sig_file[2], (int) sig_file[1]); //FileSize of x (usually 32 byte) is in second Byte[1] (first Byte [0] only for sizes higher than 255), data begin at third byte [2]
		memcpy(signature->y, &sig_file[(int) sig_file[1] + 4],
				(int) sig_file[(int) sig_file[1] + 3]); //databegin of y: size from x + 4 (2*2 size byte), length in second byte after x blob (see above)

		//convert TPM Public_key x and y big endian format to little endian (needed by sgx).
		SWAP_ENDIAN_32B(signature->x);
		SWAP_ENDIAN_32B(signature->y);

		if (EXTENDED_DEBUG) {
			fprintf(OUTPUT, "\nsignature->x - \n");
			PRINT_BYTE_ARRAY(OUTPUT, &(signature->x), sizeof(signature->x));
			fprintf(OUTPUT, "\nsignature->y - \n");
			PRINT_BYTE_ARRAY(OUTPUT, &(signature->y), sizeof(signature->y));
		}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Start TPM-Verifier with shared-secret-token, if attestation passed
		if (attestation_passed) {
			fprintf(OUTPUT,
					"\nSecret successfully received from server. Started Attestation-Verify");
			uint32_t ver_msg_size = sizeof(tpm_enc_att_state_response_message_t);
			tpm_enc_att_state_response_message_t *p_ver_msg_out =
					(tpm_enc_att_state_response_message_t *) malloc(
							ver_msg_size);

			if (EXTENDED_DEBUG) {
				printf("App, request ciphertext: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_body->ciphertext,
						sizeof(ias_platform_info_blob_t));
				printf("App, request mac: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_body->mac,
						SAMPLE_MAC_SIZE);
				printf("App, request Nonce: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_body->nonce.nonce,
						AES_GCM_IV_SIZE);
			}

			ret = secure_verify(enclave_id, &status, context,
					p_att_result_msg_body,
					sizeof(tpm_enc_att_state_request_message_t), public_key,
					attest_file, attest_size, signature, p_ver_msg_out,
					ver_msg_size);

			if (EXTENDED_DEBUG) {
				printf("App, response ciphertext: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_ver_msg_out->ciphertext,
						sizeof(tpm_platform_info_blob_t));
				printf("App, response mac: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_ver_msg_out->mac, SAMPLE_MAC_SIZE);
				printf("App, response Nonce: \n");
				PRINT_BYTE_ARRAY(OUTPUT, p_ver_msg_out->nonce.nonce,
						AES_GCM_IV_SIZE);
			}

			if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
				fprintf(OUTPUT, "\nError, Verify TPM Signature ...");
				goto CLEANUP;
			}

			fprintf(OUTPUT,
					"\n!!!TPM VERIFY SUCCESS - on sgx App side. Sending message to Remote-Party\n");

			p_ver_msg_full = (ra_samp_request_header_t*) malloc(
					sizeof(ra_samp_request_header_t) + ver_msg_size);

			if (NULL == p_ver_msg_full) {
				ret = -1;
				goto CLEANUP;
			}
			p_ver_msg_full->type = TYPE_RA_TPM_ATT_RESPONSE;
			p_ver_msg_full->size = ver_msg_size;
			if (memcpy_s(&p_ver_msg_full->body, ver_msg_size, p_ver_msg_out,
					ver_msg_size)) {
				fprintf(OUTPUT,
						"\nError: INTERNAL ERROR - memcpy failed in [%s].",
						__FUNCTION__);
				ret = -1;
				goto CLEANUP;
			}

			ret = ra_network_send_receive(
					"http://SampleServiceProvider.intel.com/", p_ver_msg_full,
					NULL);
			if (ret) {
				ret = -1;
				fprintf(OUTPUT, "\nError, sending tpm_ver_msg failed [%s].",
						__FUNCTION__);
				goto CLEANUP;
			}

		}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	}

CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context)
    {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        }
        else
        {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.\n");
    }

    sgx_destroy_enclave(enclave_id);

    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
		printf("......\n");
    ra_free_network_response_buffer(p_att_result_msg_full);
	printf("......\n");


    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);
    printf("\nEnter a character before exit ...\n");
    getchar();
    return ret;
}

