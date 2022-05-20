#include "kmippp.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sstream>
#include <stdexcept>

#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_locate.h"

namespace kmippp {
namespace {
void raise(const std::string& what) {
    std::ostringstream msg;
    msg << what << ": " << ERR_reason_error_string(ERR_get_error());
    throw std::runtime_error(msg.str());
};
}  // namespace

void context::ssl_ctx_deleter::operator()(SSL_CTX* p) const noexcept {
    if (p) {
        SSL_CTX_free(p);
    }
}

void context::bio_deleter::operator()(BIO* p) const noexcept {
    if (p) {
        BIO_free_all(p);
    }
}

context::context(const std::string& server_address,
                 const std::string& server_port,
                 const std::string& client_cert_fn,
                 const std::string& ca_cert_fn)
    : ctx_(SSL_CTX_new(SSLv23_method()), ssl_ctx_deleter()) {
    if (!ctx_) {
        raise("Creating an SSL context failed");
    }
    if (SSL_CTX_use_certificate_chain_file(ctx_.get(), client_cert_fn.c_str()) != 1) {
        raise("Loading the client certificate failed");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_.get(), client_cert_fn.c_str(), SSL_FILETYPE_PEM) != 1) {
        raise("Loading the client key failed");
    }
    if (SSL_CTX_load_verify_locations(ctx_.get(), ca_cert_fn.c_str(), nullptr) != 1) {
        raise("Loading the CA certificate failed");
    }

    bio_ = std::unique_ptr<BIO, bio_deleter>(BIO_new_ssl_connect(ctx_.get()), bio_deleter());
    if (!bio_) {
        raise("Creating a connection object failed");
    }

    SSL *ssl = nullptr;
    BIO_get_ssl(bio_.get(), &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio_.get(), server_address.c_str());
    BIO_set_conn_port(bio_.get(), server_port.c_str());
    if (BIO_do_connect(bio_.get()) != 1) {
        std::ostringstream what;
        what << "Failed to connect to '" << server_address << ":" << server_port << "'";
        raise(what.str());
    }
}

context::~context() = default;
context::context(context&&) noexcept = default;
context& context::operator=(context&&) noexcept = default;

context::id_t context::op_create(const name_t& name, const name_t& group) {
    Attribute a[5];
    for(int i = 0; i < 5; i++) {
        kmip_init_attribute(&a[i]);
    }
    
    enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;
    
    int32 length = 256;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;

    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    a[2].value = &mask;

    Name ts;
    TextString ts2 = {0,0};
    ts2.value = const_cast<char*>(name.c_str());
    ts2.size = kmip_strnlen_s(ts2.value, 250);
    ts.value = &ts2;
    ts.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    a[3].type = KMIP_ATTR_NAME;
    a[3].value = &ts;

    TextString gs2 = {0,0};
    gs2.value = const_cast<char*>(group.c_str());
    gs2.size = kmip_strnlen_s(gs2.value, 250);
    a[4].type = KMIP_ATTR_OBJECT_GROUP;
    a[4].value = &gs2;
    
    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = ARRAY_LENGTH(a);


    int id_max_len = 64;
    char* idp = nullptr;
    int result = kmip_bio_create_symmetric_key(bio_.get(), &ta, &idp, &id_max_len);

    std::string ret;
    if(idp != nullptr) {
      ret = std::string(idp, id_max_len);
      free(idp);
    }

    if(result != 0) {
      return "";
    }

    return ret;
}

context::id_t context::op_register(const name_t& name, const name_t& group, const key_t& key) {
    Attribute a[5];
    for(int i = 0; i < 5; i++) {
        kmip_init_attribute(&a[i]);
    }
    
    enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;
    
    int32 length = key.size()*8;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;

    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    a[2].value = &mask;

    Name ts;
    TextString ts2 = {0,0};
    ts2.value = const_cast<char*>(name.c_str());
    ts2.size = kmip_strnlen_s(ts2.value, 250);
    ts.value = &ts2;
    ts.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    a[3].type = KMIP_ATTR_NAME;
    a[3].value = &ts;
    
    TextString gs2 = {0,0};
    gs2.value = const_cast<char*>(group.c_str());
    gs2.size = kmip_strnlen_s(gs2.value, 250);
    a[4].type = KMIP_ATTR_OBJECT_GROUP;
    a[4].value = &gs2;

    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = ARRAY_LENGTH(a);


    int id_max_len = 64;
    char* idp = nullptr;
    auto key_data = reinterpret_cast<char*>(const_cast<unsigned char*>(key.data()));
    int result =
        kmip_bio_register_symmetric_key(bio_.get(), &ta, key_data, key.size(), &idp, &id_max_len);

    std::string ret;
    if(idp != nullptr) {
      ret = std::string(idp, id_max_len);
      free(idp);
    }

    if(result != 0) {
      return "";
    }

    return ret;
}

context::key_t context::op_get(const id_t& id) {
    int key_len = 0;
    char* keyp = nullptr;
    int result = kmip_bio_get_symmetric_key(
        bio_.get(), const_cast<char*>(id.c_str()), id.length(), &keyp, &key_len);

    key_t key(key_len);
    if(keyp != nullptr) {
      memcpy(key.data(), keyp, key_len);
      free(keyp);
    }

    if(result != 0) {
      return {};
    }

    return key;
}

bool context::op_destroy(const id_t& id) {
    return kmip_bio_destroy_symmetric_key(bio_.get(), const_cast<char*>(id.c_str()), id.length()) ==
        KMIP_OK;
}

context::name_t context::op_get_name_attr(const id_t& id) {
    int key_len = 0;
    char* keyp = nullptr;
    int result = kmip_bio_get_name_attribute(
        bio_.get(), const_cast<char*>(id.c_str()), id.length(), &keyp, &key_len);

    name_t key;
    if(keyp != nullptr) {
      key = keyp;
      free(keyp);
    }

    if(result != 0) {
      return {};
    }

    return key;
}

context::ids_t context::op_locate(const name_t& name) {
    Attribute a[3];
    for(int i = 0; i < 3; i++) {
        kmip_init_attribute(&a[i]);

    }
    object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
    a[0].type = KMIP_ATTR_OBJECT_TYPE;
    a[0].value = &loctype;

    Name ts;
    TextString ts2 = {0,0};
    ts2.value = const_cast<char*>(name.c_str());
    ts2.size = kmip_strnlen_s(ts2.value, 250);
    ts.value = &ts2;
    ts.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    a[1].type = KMIP_ATTR_NAME;
    a[1].value = &ts;
    
    int upto = 0;
    int all = 1; // TMP
    ids_t ret;

    LocateResponse locate_result;

    while (upto < all) {
      // 16 is hard coded: seems like the most vault supports?
      int result = kmip_bio_locate(bio_.get(), a, 2, &locate_result, 16, upto);

      if (result != 0) {
        return {};
      }

      for (std::size_t i = 0; i < locate_result.ids_size; ++i) {
          ret.push_back(locate_result.ids[i]);
      }
      if (locate_result.located_items != 0) {
        all = locate_result.located_items;  // shouldn't change after its != 1
      } else {
        // Dummy server sometimes returns 0 for located_items
        all += locate_result.ids_size;
        if(locate_result.ids_size == 0) {
          --all;
        }
      }
      upto += locate_result.ids_size;
    }

    return ret;
}

context::ids_t context::op_locate_by_group(const name_t& group) {
    Attribute a[2];
    for(int i = 0; i < 2; i++) {
        kmip_init_attribute(&a[i]);
    }
    
    object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
    a[0].type = KMIP_ATTR_OBJECT_TYPE;
    a[0].value = &loctype;

    TextString ts2 = {0,0};
    ts2.value = const_cast<char*>(group.c_str());
    ts2.size = kmip_strnlen_s(ts2.value, 250);
    a[1].type = KMIP_ATTR_OBJECT_GROUP;
    a[1].value = &ts2;
    
    TemplateAttribute ta = {0};
    ta.attributes = a;
    ta.attribute_count = ARRAY_LENGTH(a);

    int upto = 0;
    int all = 1; // TMP
    ids_t ret;

    LocateResponse locate_result;

    while (upto < all) {
      int result = kmip_bio_locate(bio_.get(), a, 2, &locate_result, 16, upto);

      if (result != 0) {
        return {};
      }

      for (std::size_t i = 0; i < locate_result.ids_size; ++i) {
          ret.push_back(locate_result.ids[i]);
      }
      if (locate_result.located_items != 0) {
        all = locate_result.located_items;  // shouldn't change after its != 1
      } else {
        // Dummy server sometimes returns 0 for located_items
        all += locate_result.ids_size;
        if(locate_result.ids_size == 0) {
          --all;
        }
      }
      upto += locate_result.ids_size;
    }


    return ret;
}

context::ids_t context::op_all() {
    Attribute a[1];
    for(int i = 0; i < 1; i++) {
        kmip_init_attribute(&a[i]);
    }
    
    object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
    a[0].type = KMIP_ATTR_OBJECT_TYPE;
    a[0].value = &loctype;

    LocateResponse locate_result;

    int upto = 0;
    int all = 1; // TMP
    ids_t ret;

    while (upto < all) {
      int result = kmip_bio_locate(bio_.get(), a, 1, &locate_result, 16, upto);

      if (result != 0) {
        return {};
      }

      for (std::size_t i = 0; i < locate_result.ids_size; ++i) {
          ret.push_back(locate_result.ids[i]);
      }
      if (locate_result.located_items != 0) {
        all = locate_result.located_items;  // shouldn't change after its != 1
      } else {
        // Dummy server sometimes returns 0 for located_items
        all += locate_result.ids_size;
        if(locate_result.ids_size == 0) {
          --all;
        }
      }
      upto += locate_result.ids_size;
    }

    return ret;
}

}
