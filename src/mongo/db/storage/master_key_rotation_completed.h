#pragma once

#include <stdexcept>

namespace mongo {

/// @brief Thrown as a way to notify that key rotation has completed _successfully_.
///
/// @todo Try to refactor the code so that thre is no need in throwing an exception
/// in case of successfull execution.
struct MasterKeyRotationCompleted : std::runtime_error {
    explicit MasterKeyRotationCompleted(const char* msg) : std::runtime_error(msg) {}
};

}  // namespace mongo
