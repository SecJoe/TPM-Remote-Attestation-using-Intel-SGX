----------------------------
Summary
----------------------------
Verifiy a TPM Quote in an enclave and attest the verification state to a remote party over a secure connection channel.

----------------------------
The whole code in more detail:
----------------------------
- I use the Intel SGX Remote Attestation Sample Code to realize a Remote Attestation of an
  enclave to a remote party which is also called service provider. 
- Also I adpot the secure session establishment embedded from the Remote Attestation example
- On top of that I have implemented enclave which verfiies the Quote (check the Signature) and
  also compare the attested PCR values against the intended PCR values defined from the enclave
  author. In the implemention of this project I had to solve some additional milestones like: 

	a) BIG-Endian to Little Endian conversion (8 byte type and 32 byte type). 
	b) The standard SGX crypto library does not support RSA so I had to use ECC for 
the TPM Quotes.
	c) There is no library for unstusted code (service-provider aka. remote party) to 
decrypt AES packets. So later in the process when I report the verification state 
to the remote party I had to decrypt the AES packet with OpenSSL.

- Intel Sample Code: https://github.com/01org/linux-sgx/tree/master/SampleCode/RemoteAttestation

----------------------------
My project in more detail:
----------------------------
- In my project I load a TPM Quote in the App (untrusted code) memory. 
- After that I check some requirements like
	a) Size limitations of data blocks into the Quote 
	b) limitations regarding the used signature algorithm by the TPM. 
SGX does not support RSA in the standard sgx_tcypto library. So is had to 
use Elliptic Curve Digital Signature Algorithm (ECDSA) in the TPM Quotes. 
Also SGX supprts only the specific ECC curves (secp256r1 also called 
NIST P-256, P-256 or prime256v1). I will check that requirements too.
	c)  ...................

Later, I will add later more text............................................................





------------------------------------
How to Build/Execute the project
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
        $ make
3. Execute the binary directly:
    $ ./app
