#include <memory>
#include <cstdint>
#include <vector>
#include <string>

extern "C" {
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
}

namespace kmippp {
  class context {
    public:
      using key_t = std::vector<unsigned char>;
      using id_t = std::string;
      using ids_t = std::vector<std::string>;
      using name_t = std::string;

      context(const std::string& server_address,
              const std::string& server_port,
              const std::string& client_cert_fn,
              const std::string& ca_cert_fn);
      ~context();

      context(context &&) noexcept = default;
      context(context const&) = delete;

      context& operator=(context&&) noexcept = default;
      context& operator=(context const&) = delete;

      // KMIP::create operation, generates a new AES symmetric key on the server
      id_t op_create(const name_t& name, const name_t& group);

      // KMIP::register operation, stores an existing symmetric key on the server
      id_t op_register(const name_t& name, const name_t& group, const key_t& k);

      // KMIP::get operation, retrieve a symmetric key by id
      key_t op_get(const id_t& id);

      // KMIP::get_attribute operation, retrieve the name of a symmetric key by id
      name_t op_get_name_attr(const id_t& id);

      // KMIP::locate operation, retrieve symmetric keys by name
      // note: name can be empty, and will retrieve all keys
      ids_t op_locate(const name_t& name);

      ids_t op_locate_by_group(const name_t& group);

      bool op_destroy(const id_t& id);

      // KMIP::locate operation, retrieve all symmetric keys
      // note: name can be empty, and will retrieve all keys
      ids_t op_all();

    private:
      SSL_CTX *ctx_ = nullptr;
      BIO* bio_;
  };
}
