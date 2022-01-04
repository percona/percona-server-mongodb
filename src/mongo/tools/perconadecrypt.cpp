/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#include <iostream>

#include <boost/crc.hpp>
#include <boost/filesystem.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "mongo/base/init.h"
#include "mongo/base/initializer.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/encryption_vault.h"
#include "mongo/db/encryption/encryption_kmip.h"
#include "mongo/tools/perconadecrypt_options.h"
#include "mongo/util/base64.h"
#include "mongo/util/exit_code.h"
#include "mongo/util/str.h"  // for str::stream()!

namespace mongo {

MONGO_INITIALIZER(SetupOpenSSL)(InitializerContext*) {
    //SSL_library_init();
    //SSL_load_error_strings();
    ERR_load_crypto_strings();

    return Status::OK();
}

namespace {

constexpr int _key_len = 32;
unsigned char _masterkey[_key_len];

class EVPCipherCtx {
public:
    EVPCipherCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_init(&_ctx_value);
#else
        _ctx= EVP_CIPHER_CTX_new();
#endif
    }

    ~EVPCipherCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(&_ctx_value);
#else
        EVP_CIPHER_CTX_free(_ctx);
#endif
    }

    operator EVP_CIPHER_CTX* () {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        return &_ctx_value;
#else
        return _ctx;
#endif
    }

private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx_value;
#else
    EVP_CIPHER_CTX *_ctx{nullptr};
#endif
};

// callback for ERR_print_errors_cb
static int err_print_cb(const char *str, size_t len, void *param) {
    std::cerr << str;
    return 1;
}

int handleCryptoErrors() {
    ERR_print_errors_cb(&err_print_cb, nullptr);
    return 1;
}

int printErrorMsg(char const* msg) {
    std::cerr << msg << std::endl;
    return 1;
}

int decryptCBC(boost::uintmax_t fsize, std::ifstream& src, std::ofstream& dst) {
    boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32c;
    auto _cipher = EVP_aes_256_cbc();
    auto _iv_len = EVP_CIPHER_iv_length(_cipher);
    const size_t block_size = 8 * 1024;
    const size_t tag_size = 4; // CRC32C value size
    EVPCipherCtx ctx;

    uint32_t checksum;
    if (!src.read((char*)&checksum, tag_size))
        return printErrorMsg("Cannot read from encrypted file");
    fsize -= tag_size;

    {
        char iv[_iv_len];
        if (!src.read(iv, _iv_len))
            return printErrorMsg("Cannot read from encrypted file");
        fsize -= _iv_len;
        if (1 != EVP_DecryptInit_ex(ctx, _cipher, nullptr, _masterkey, (const unsigned char*)iv))
            return handleCryptoErrors();
    }

    char e_buf[block_size]; // encrypted buffer
    char d_buf[block_size + 32]; // decrypted buffer
    int decrypted_len = 0;
    while (fsize > 0) {
        size_t to_read = block_size;
        if (fsize < block_size)
            to_read = fsize;
        if (!src.read(e_buf, to_read))
            return printErrorMsg("Cannot read from encrypted file");
        fsize -= to_read;
        if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)d_buf, &decrypted_len, (unsigned char*)e_buf, to_read))
            return handleCryptoErrors();
        if (!dst.write(d_buf, decrypted_len))
            return printErrorMsg("Cannot write to decrypted file");
        crc32c.process_bytes(d_buf, decrypted_len);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)d_buf, &decrypted_len))
        return handleCryptoErrors();
    if (!dst.write(d_buf, decrypted_len))
        return printErrorMsg("Cannot write to decrypted file");
    crc32c.process_bytes(d_buf, decrypted_len);

    if (crc32c() != checksum)
        return printErrorMsg("Checksum does not match stored value.");

    return EXIT_SUCCESS;
}

int decryptGCM(boost::uintmax_t fsize, std::ifstream& src, std::ofstream& dst) {
    auto _cipher = EVP_aes_256_gcm();
    auto _iv_len = EVP_CIPHER_iv_length(_cipher);
    const size_t block_size = 8 * 1024;
    const size_t _gcm_tag_len = 16; // GCM tag len
    EVPCipherCtx ctx;

    uint8_t gcm_tag[_gcm_tag_len];
    if (!src.read((char*)gcm_tag, _gcm_tag_len))
        return printErrorMsg("Cannot read from encrypted file");
    fsize -= _gcm_tag_len;

    {
        char iv[_iv_len];
        if (!src.read(iv, _iv_len))
            return printErrorMsg("Cannot read from encrypted file");
        fsize -= _iv_len;
        if (1 != EVP_DecryptInit_ex(ctx, _cipher, nullptr, _masterkey, (const unsigned char*)iv))
            return handleCryptoErrors();
    }

    char e_buf[block_size]; // encrypted buffer
    char d_buf[block_size + 32]; // decrypted buffer
    int decrypted_len = 0;
    while (fsize > 0) {
        size_t to_read = block_size;
        if (fsize < block_size)
            to_read = fsize;
        if (!src.read(e_buf, to_read))
            return printErrorMsg("Cannot read from encrypted file");
        fsize -= to_read;
        if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)d_buf, &decrypted_len, (unsigned char*)e_buf, to_read))
            return handleCryptoErrors();
        if (!dst.write(d_buf, decrypted_len))
            return printErrorMsg("Cannot write to decrypted file");
    }

    // Set expected tag value. Works in OpenSSL 1.0.1d and later
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, _gcm_tag_len, gcm_tag))
        return handleCryptoErrors();

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)d_buf, &decrypted_len))
        return handleCryptoErrors();
    if (!dst.write(d_buf, decrypted_len))
        return printErrorMsg("Cannot write to decrypted file");

    return EXIT_SUCCESS;
}

}


int decryptMain(int argc, char** argv, char** envp) {
    int ret{EXIT_BADOPTIONS};
    runGlobalInitializersOrDie(argc, argv, envp);

    try{
        std::string encoded_key;
        if (!encryptionGlobalParams.kmipServerName.empty()) {
            std::cout << "Loading encryption key from the KMIP server" << std::endl;
            encoded_key = kmipReadKey();
        } else if (!encryptionGlobalParams.vaultServerName.empty()) {
            if (encryptionGlobalParams.vaultToken.empty()) {
                if (!boost::filesystem::exists(encryptionGlobalParams.vaultTokenFile)) {
                    throw std::runtime_error(std::string("specified Vault tokne file doesn't exist: ")
                                                         + encryptionGlobalParams.vaultTokenFile);
                }
                std::ifstream f{encryptionGlobalParams.vaultTokenFile};
                if (!f.is_open()) {
                    throw std::runtime_error(std::string("cannot open specified Vault token file: ")
                                                         + encryptionGlobalParams.vaultTokenFile);
                }
                f >> encryptionGlobalParams.vaultToken;
            }
            std::cout << "Loading encryption key from the Vault server" << std::endl;
            encoded_key = vaultReadKey();
        } else {
            std::cout << "Loading encryption key from: " << encryptionGlobalParams.encryptionKeyFile << std::endl;
            if (!boost::filesystem::exists(encryptionGlobalParams.encryptionKeyFile)) {
                throw std::runtime_error(std::string("specified encryption key file doesn't exist: ")
                                                     + encryptionGlobalParams.encryptionKeyFile);
            }
            std::ifstream f{encryptionGlobalParams.encryptionKeyFile};
            if (!f.is_open()) {
                throw std::runtime_error(std::string("cannot open specified encryption key file: ")
                                                     + encryptionGlobalParams.encryptionKeyFile);
            }
            f >> encoded_key;
        }
        auto key = base64::decode(encoded_key);
        if (key.length() != _key_len) {
            throw std::runtime_error(str::stream() << "encryption key length should be " << _key_len << " bytes");
        }
        memcpy(_masterkey, key.c_str(), _key_len);
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_BADOPTIONS;
    }

    try{
        std::cout << "Input (encrypted) file: " << perconaDecryptGlobalParams.inputPath << std::endl;
        if (!boost::filesystem::exists(perconaDecryptGlobalParams.inputPath)) {
            throw std::runtime_error(std::string("specified encrypted file doesn't exist: ")
                                                 + perconaDecryptGlobalParams.inputPath);
        }

        auto fsize{boost::filesystem::file_size(perconaDecryptGlobalParams.inputPath)};

        std::ifstream src{};
        src.open(perconaDecryptGlobalParams.inputPath, std::ios::binary);
        if (!src.is_open()) {
            throw std::runtime_error(std::string("cannot open specified encrypted file: ")
                                                 + perconaDecryptGlobalParams.inputPath);
        }

        std::cout << "Output (decrypted) file: " << perconaDecryptGlobalParams.outputPath << std::endl;
        std::ofstream dst{};
        dst.open(perconaDecryptGlobalParams.outputPath, std::ios::binary);
        if (!dst.is_open()) {
            throw std::runtime_error(std::string("cannot open specified decrypted result file for writing: ")
                                                 + perconaDecryptGlobalParams.inputPath);
        }

        std::cout << "Executing decryption with cipher mode: " << encryptionGlobalParams.encryptionCipherMode << std::endl;
        if (encryptionGlobalParams.encryptionCipherMode == "AES256-CBC")
            ret = decryptCBC(fsize, src, dst);
        else if ((encryptionGlobalParams.encryptionCipherMode == "AES256-GCM"))
            ret = decryptGCM(fsize, src, dst);

        if (ret)
            std::cerr << "Decryption failed. Decrypted data is not trustworthy." << std::endl;
        else
            std::cout << "Decryption succeeded." << std::endl;

    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_BADOPTIONS;
    }
    return ret;
}

}  // namespace mongo

int main(int argc, char* argv[], char** envp) {
    return mongo::decryptMain(argc, argv, envp);
}
