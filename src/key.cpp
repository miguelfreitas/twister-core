// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "key.h"

#ifdef DEBUG_ECIES
#include "util.h"
#endif

// anonymous namespace with local implementation code (OpenSSL interaction)
namespace {

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

void * ecies_key_derivation(const void *input, size_t ilen, void *output, size_t *olen) {
    if (*olen < SHA512_DIGEST_LENGTH) {
            return NULL;
    }
    *olen = SHA512_DIGEST_LENGTH;
    return SHA512(static_cast<const unsigned char*>(input), ilen, static_cast<unsigned char*>(output));
}

// RAII Wrapper around OpenSSL's EC_KEY
class CECKey {
private:
    EC_KEY *pkey;

public:
    CECKey() {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        assert(pkey != NULL);
    }

    ~CECKey() {
        EC_KEY_free(pkey);
    }

    void GetSecretBytes(unsigned char vch[32]) const {
        const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
        assert(bn);
        int nBytes = BN_num_bytes(bn);
        int n=BN_bn2bin(bn,&vch[32 - nBytes]);
        assert(n == nBytes);
        memset(vch, 0, 32 - nBytes);
    }

    void SetSecretBytes(const unsigned char vch[32]) {
        BIGNUM bn;
        BN_init(&bn);
        bool check = BN_bin2bn(vch, 32, &bn);
        assert(check);
        check = EC_KEY_regenerate_key(pkey, &bn);
        assert(check);
        BN_clear_free(&bn);
    }

    void GetPrivKey(CPrivKey &privkey, bool fCompressed) {
        EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
        int nSize = i2d_ECPrivateKey(pkey, NULL);
        assert(nSize);
        privkey.resize(nSize);
        unsigned char* pbegin = &privkey[0];
        int nSize2 = i2d_ECPrivateKey(pkey, &pbegin);
        assert(nSize == nSize2);
    }

    bool SetPrivKey(const CPrivKey &privkey) {
        const unsigned char* pbegin = &privkey[0];
        if (d2i_ECPrivateKey(&pkey, &pbegin, privkey.size())) {
            // d2i_ECPrivateKey returns true if parsing succeeds.
            // This doesn't necessarily mean the key is valid.
            if (EC_KEY_check_key(pkey))
                return true;
        }
        return false;
    }

    void GetPubKey(CPubKey &pubkey, bool fCompressed) {
        EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
        int nSize = i2o_ECPublicKey(pkey, NULL);
        assert(nSize);
        assert(nSize <= 65);
        unsigned char c[65];
        unsigned char *pbegin = c;
        int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
        assert(nSize == nSize2);
        pubkey.Set(&c[0], &c[nSize]);
    }

    bool SetPubKey(const CPubKey &pubkey) {
        const unsigned char* pbegin = pubkey.begin();
        return o2i_ECPublicKey(&pkey, &pbegin, pubkey.size());
    }

    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) {
        unsigned int nSize = ECDSA_size(pkey);
        vchSig.resize(nSize); // Make sure it is big enough
        bool check = ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], &nSize, pkey);
        assert(check);
        vchSig.resize(nSize); // Shrink to fit actual size
        return true;
    }

    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
        // -1 = error, 0 = bad sig, 1 = good
        if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
            return false;
        return true;
    }

    bool SignCompact(const uint256 &hash, unsigned char *p64, int &rec) {
        bool fOk = false;
        ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
        if (sig==NULL)
            return false;
        memset(p64, 0, 64);
        int nBitsR = BN_num_bits(sig->r);
        int nBitsS = BN_num_bits(sig->s);
        if (nBitsR <= 256 && nBitsS <= 256) {
            CPubKey pubkey;
            GetPubKey(pubkey, true);
            for (int i=0; i<4; i++) {
                CECKey keyRec;
                if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1) {
                    CPubKey pubkeyRec;
                    keyRec.GetPubKey(pubkeyRec, true);
                    if (pubkeyRec == pubkey) {
                        rec = i;
                        fOk = true;
                        break;
                    }
                }
            }
            assert(fOk);
            BN_bn2bin(sig->r,&p64[32-(nBitsR+7)/8]);
            BN_bn2bin(sig->s,&p64[64-(nBitsS+7)/8]);
        }
        ECDSA_SIG_free(sig);
        return fOk;
    }

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    bool Recover(const uint256 &hash, const unsigned char *p64, int rec)
    {
        if (rec<0 || rec>=3)
            return false;
        ECDSA_SIG *sig = ECDSA_SIG_new();
        BN_bin2bn(&p64[0],  32, sig->r);
        BN_bin2bn(&p64[32], 32, sig->s);
        bool ret = ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), rec, 0) == 1;
        ECDSA_SIG_free(sig);
        return ret;
    }

    /**
     * @file /cryptron/ecies.c
     *
     * @brief ECIES encryption/decryption functions.
     *
     * $Author: Ladar Levison $
     * $Website: http://lavabit.com $
     * $Date: 2010/08/06 06:02:03 $
     * $Revision: a51931d0f81f6abe29ca91470931d41a374508a7 $
     *
     */
    bool Encrypt(std::string const &vchText, ecies_secure_t &cryptex)
    {
        size_t length = vchText.size();
        size_t envelope_length, block_length, key_length;
        if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
#ifdef DEBUG_ECIES
            printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}\n",
                   SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
#endif
            return false;
        }

        // Create the ephemeral key used specifically for this block of data.
        EC_KEY *ephemeral;
        if (!(ephemeral = EC_KEY_new())) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to generate the ephemeral key.\n");
#endif
                return false;
        } else {
            const EC_GROUP *group = NULL;
            if( !(group = EC_KEY_get0_group(pkey))) {
#ifdef DEBUG_ECIES
                printf("An error occurred in EC_KEY_get0_group.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
            }
            if (EC_KEY_set_group(ephemeral, group) != 1) {
#ifdef DEBUG_ECIES
                    printf("EC_KEY_set_group failed.\n");
#endif
                    EC_KEY_free(ephemeral);
                    return false;
            }
        }

        if (EC_KEY_generate_key(ephemeral) != 1) {
#ifdef DEBUG_ECIES
                printf("EC_KEY_generate_key failed.\n");
#endif
                return false;
        }

        // Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
        // SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
        unsigned char envelope_key[SHA512_DIGEST_LENGTH];
        if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH,
                             EC_KEY_get0_public_key(pkey),
                             ephemeral,
                             ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to compute the envelope key.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
        }

        // Determine the envelope and block lengths so we can allocate a buffer for the result.
        if ((block_length = EVP_CIPHER_block_size(ECIES_CIPHER)) == 0 ||
                 block_length > EVP_MAX_BLOCK_LENGTH ||
                 (envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral),
                                                       POINT_CONVERSION_COMPRESSED, NULL, 0, NULL)) == 0) {
#ifdef DEBUG_ECIES
                printf("Invalid block or envelope length. {block = %zu / envelope = %zu}\n", block_length, envelope_length);
#endif
                EC_KEY_free(ephemeral);
                return false;
        }

        // We use a conditional to pad the length if the input buffer is not evenly divisible by the block size.
        cryptex.key.resize(envelope_length);
        cryptex.mac.resize(EVP_MD_size(ECIES_HASHER));
        cryptex.orig = length;
        cryptex.body.resize(length + (length % block_length ? (block_length - (length % block_length)) : 0));

        // Store the public key portion of the ephemeral key.
        if (EC_POINT_point2oct(EC_KEY_get0_group(ephemeral),
                               EC_KEY_get0_public_key(ephemeral),
                               POINT_CONVERSION_COMPRESSED,
                               reinterpret_cast<unsigned char*>(&cryptex.key[0]), envelope_length,
                               NULL) != envelope_length) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to record the public portion of the envelope key.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
        }
        // The envelope key has been stored so we no longer need to keep the keys around.
        EC_KEY_free(ephemeral);

        unsigned char iv[EVP_MAX_IV_LENGTH], block[EVP_MAX_BLOCK_LENGTH];
        // For now we use an empty initialization vector.
        memset(iv, 0, EVP_MAX_IV_LENGTH);

        // Setup the cipher context, the body length, and store a pointer to the body buffer location.
        EVP_CIPHER_CTX cipher;
        EVP_CIPHER_CTX_init(&cipher);

        unsigned char *body = reinterpret_cast<unsigned char *>(&cryptex.body[0]);
        int body_length = cryptex.body.size();

        // Initialize the cipher with the envelope key.
        if (EVP_EncryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1 ||
            EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 ||
                EVP_EncryptUpdate(&cipher, body, &body_length, reinterpret_cast<const unsigned char *>(&vchText[0]), length - (length % block_length)) != 1) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to secure the data using the chosen symmetric cipher.\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }
        // Check whether all of the data was encrypted. If they don't match up, we either have a partial block remaining, or an error occurred.
        if (body_length != (int)length) {
                // Make sure all that remains is a partial block, and their wasn't an error.
                if (length - body_length >= block_length) {
#ifdef DEBUG_ECIES
                        printf("Unable to secure the data using the chosen symmetric cipher.\n");
#endif
                        EVP_CIPHER_CTX_cleanup(&cipher);
                        return false;
                }

                // Copy the remaining data into our partial block buffer. The memset() call ensures any extra bytes will be zero'ed out.
                memset(block, 0, EVP_MAX_BLOCK_LENGTH);
                memcpy(block, vchText.data() + body_length, length - body_length);

                // Advance the body pointer to the location of the remaining space, and calculate just how much room is still available.
                body += body_length;
                if ((body_length = cryptex.body.size() - body_length) < 0) {
#ifdef DEBUG_ECIES
                        printf("The symmetric cipher overflowed!\n");
#endif
                        EVP_CIPHER_CTX_cleanup(&cipher);
                        return false;
                }

                // Pass the final partially filled data block into the cipher as a complete block. The padding will be removed during the decryption process.
                else if (EVP_EncryptUpdate(&cipher, body, &body_length, block, block_length) != 1) {
#ifdef DEBUG_ECIES
                        printf("Unable to secure the data using the chosen symmetric cipher\n");
#endif
                        EVP_CIPHER_CTX_cleanup(&cipher);
                        return false;
                }
        }

        // Advance the pointer, then use pointer arithmetic to calculate how much of the body buffer has been used. The complex logic is needed so that we get
        // the correct status regardless of whether there was a partial data block.
        body += body_length;
        if ((body_length = cryptex.body.size() - (body - reinterpret_cast<const unsigned char *>(cryptex.body.data()))) < 0) {
#ifdef DEBUG_ECIES
                printf("The symmetric cipher overflowed!\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }

        else if (EVP_EncryptFinal_ex(&cipher, body, &body_length) != 1) {
#ifdef DEBUG_ECIES
                printf("Unable to secure the data using the chosen symmetric cipher.\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }

        EVP_CIPHER_CTX_cleanup(&cipher);

        // Generate an authenticated hash which can be used to validate the data during decryption.
        HMAC_CTX hmac;
        HMAC_CTX_init(&hmac);
        unsigned int mac_length = cryptex.mac.size();

        // At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
#if (OPENSSL_VERSION_NUMBER < 0x000909000)
	HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL);
	HMAC_Update(&hmac, reinterpret_cast<const unsigned char *>(cryptex.body.data()), cryptex.body.size());
	HMAC_Final(&hmac, reinterpret_cast<unsigned char *>(&cryptex.mac[0]), &mac_length);
#else
        if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1 ||
            HMAC_Update(&hmac, reinterpret_cast<const unsigned char *>(cryptex.body.data()), cryptex.body.size()) != 1 ||
            HMAC_Final(&hmac, reinterpret_cast<unsigned char *>(&cryptex.mac[0]), &mac_length) != 1) {
#ifdef DEBUG_ECIES
                printf("Unable to generate a data authentication code.\n");
#endif
                HMAC_CTX_cleanup(&hmac);
                return false;
        }
#endif

        HMAC_CTX_cleanup(&hmac);
        return true;

    }

    bool Decrypt(ecies_secure_t const &cryptex, std::string &vchText )
    {
        size_t key_length;
        if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
#ifdef DEBUG_ECIES
            printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}\n",
                   SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
#endif
            return false;
        }

        // Create the ephemeral key used specifically for this block of data.
        EC_KEY *ephemeral;
        if (!(ephemeral = EC_KEY_new())) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to generate the ephemeral key.\n");
#endif
                return false;
        } else {
            const EC_GROUP *group = NULL;
            if( !(group = EC_KEY_get0_group(pkey))) {
#ifdef DEBUG_ECIES
                printf("An error occurred in EC_KEY_get0_group.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
            }
            if (EC_KEY_set_group(ephemeral, group) != 1) {
#ifdef DEBUG_ECIES
                    printf("EC_KEY_set_group failed.\n");
#endif
                    EC_KEY_free(ephemeral);
                    return false;
            }

            EC_POINT *point = NULL;
            if (!(point = EC_POINT_new(group))) {
#ifdef DEBUG_ECIES
                    printf("EC_POINT_new failed.\n");
#endif
                    EC_KEY_free(ephemeral);
                    return false;
            }

            if (EC_POINT_oct2point(group, point, reinterpret_cast<const unsigned char *>(cryptex.key.data()), cryptex.key.size(), NULL) != 1) {
#ifdef DEBUG_ECIES
                    printf("EC_POINT_oct2point failed.\n");
#endif
                    EC_KEY_free(ephemeral);
                    return false;
            }

            if (EC_KEY_set_public_key(ephemeral, point) != 1) {
#ifdef DEBUG_ECIES
                    printf("EC_KEY_set_public_key failed.\n");
#endif
                    EC_POINT_free(point);
                    EC_KEY_free(ephemeral);
                    return false;
            }
            EC_POINT_free(point);
        }

        if (EC_KEY_check_key(ephemeral) != 1) {
#ifdef DEBUG_ECIES
                printf("EC_KEY_check_key ephemeral failed.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
        }

        // Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
        // SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
        unsigned char envelope_key[SHA512_DIGEST_LENGTH];
        if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH,
                             EC_KEY_get0_public_key(ephemeral),
                             pkey,
                             ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
#ifdef DEBUG_ECIES
                printf("An error occurred while trying to compute the envelope key.\n");
#endif
                EC_KEY_free(ephemeral);
                return false;
        }

        // The envelope key material has been extracted, so we no longer need the user and ephemeral keys.
        EC_KEY_free(ephemeral);

        // Use the authenticated hash of the ciphered data to ensure it was not modified after being encrypted.
        HMAC_CTX hmac;
        HMAC_CTX_init(&hmac);
        unsigned int mac_length = EVP_MAX_MD_SIZE;
        unsigned char md[EVP_MAX_MD_SIZE];

        // At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
#if (OPENSSL_VERSION_NUMBER < 0x000909000)
        HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL);
        HMAC_Update(&hmac, reinterpret_cast<const unsigned char *>(cryptex.body.data()), cryptex.body.size());
	HMAC_Final(&hmac, md, &mac_length);
#else
        if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1 ||
            HMAC_Update(&hmac, reinterpret_cast<const unsigned char *>(cryptex.body.data()), cryptex.body.size()) != 1 ||
            HMAC_Final(&hmac, md, &mac_length) != 1) {
#ifdef DEBUG_ECIES
                printf("Unable to generate a data authentication code.\n");
#endif
                HMAC_CTX_cleanup(&hmac);
                return false;
        }
#endif

        HMAC_CTX_cleanup(&hmac);

        // We can use the generated hash to ensure the encrypted data was not altered after being encrypted.
        if (mac_length != cryptex.mac.size() || memcmp(md, cryptex.mac.data(), mac_length)) {
#ifdef DEBUG_ECIES
                printf("The authentication code was invalid! The ciphered data has been corrupted!\n");
#endif
                return false;
        }

        // Create a buffer to hold the result.
        int output_length = cryptex.body.size();
        vchText.resize(output_length+1);
        unsigned char *block, *output;
        block = output = reinterpret_cast<unsigned char *>(&vchText[0]);

        unsigned char iv[EVP_MAX_IV_LENGTH];
        // For now we use an empty initialization vector. We also clear out the result buffer just to be on the safe side.
        memset(iv, 0, EVP_MAX_IV_LENGTH);
        memset(output, 0, output_length + 1);

        // Setup the cipher context, the body length, and store a pointer to the body buffer location.
        EVP_CIPHER_CTX cipher;
        EVP_CIPHER_CTX_init(&cipher);

        // Decrypt the data using the chosen symmetric cipher.
        if (EVP_DecryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1 ||
            EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 ||
            EVP_DecryptUpdate(&cipher, block, &output_length, reinterpret_cast<const unsigned char *>(cryptex.body.data()), cryptex.body.size()) != 1) {
#ifdef DEBUG_ECIES
                printf("Unable to decrypt the data using the chosen symmetric cipher.\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }

        block += output_length;
        if ((output_length = cryptex.body.size() - output_length) != 0) {
#ifdef DEBUG_ECIES
                printf("The symmetric cipher failed to properly decrypt the correct amount of data!\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }

        if (EVP_DecryptFinal_ex(&cipher, block, &output_length) != 1) {
#ifdef DEBUG_ECIES
                printf("Unable to decrypt the data using the chosen symmetric cipher.\n");
#endif
                EVP_CIPHER_CTX_cleanup(&cipher);
                return false;
        }

        EVP_CIPHER_CTX_cleanup(&cipher);

        vchText.resize(cryptex.orig);
        return true;
    }
};

}; // end of anonymous namespace

bool CKey::Check(const unsigned char *vch) {
    // Do not convert to OpenSSL's data structures for range-checking keys,
    // it's easy enough to do directly.
    static const unsigned char vchMax[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
    };
    bool fIsZero = true;
    for (int i=0; i<32 && fIsZero; i++)
        if (vch[i] != 0)
            fIsZero = false;
    if (fIsZero)
        return false;
    for (int i=0; i<32; i++) {
        if (vch[i] < vchMax[i])
            return true;
        if (vch[i] > vchMax[i])
            return false;
    }
    return true;
}

void CKey::MakeNewKey(bool fCompressedIn) {
    do {
        RAND_bytes(vch, sizeof(vch));
    } while (!Check(vch));
    fValid = true;
    fCompressed = fCompressedIn;
}

bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn) {
    CECKey key;
    if (!key.SetPrivKey(privkey))
        return false;
    key.GetSecretBytes(vch);
    fCompressed = fCompressedIn;
    fValid = true;
    return true;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CECKey key;
    key.SetSecretBytes(vch);
    CPrivKey privkey;
    key.GetPrivKey(privkey, fCompressed);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    CECKey key;
    key.SetSecretBytes(vch);
    CPubKey pubkey;
    key.GetPubKey(pubkey, fCompressed);
    return pubkey;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    return key.Sign(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    vchSig.resize(65);
    int rec = -1;
    if (!key.SignCompact(hash, &vchSig[1], rec))
        return false;
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Decrypt(ecies_secure_t const &cryptex, std::string &vchText )
{
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    return key.Decrypt(cryptex, vchText);
}

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    if (!key.Verify(hash, vchSig))
        return false;
    return true;
}

bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != 65)
        return false;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], (vchSig[0] - 27) & ~4))
        return false;
    key.GetPubKey(*this, (vchSig[0] - 27) & 4);
    return true;
}

bool CPubKey::VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    if (vchSig.size() != 65)
        return false;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], (vchSig[0] - 27) & ~4))
        return false;
    CPubKey pubkeyRec;
    key.GetPubKey(pubkeyRec, IsCompressed());
    if (*this != pubkeyRec)
        return false;
    return true;
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    return true;
}

bool CPubKey::Decompress() {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    key.GetPubKey(*this, false);
    return true;
}

bool CPubKey::Encrypt(std::string const &vchText, ecies_secure_t &cryptex)
{
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    return key.Encrypt(vchText, cryptex);
}

