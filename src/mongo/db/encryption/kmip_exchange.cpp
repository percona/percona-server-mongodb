/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/encryption/kmip_exchange.h"

#include "mongo/db/encryption/key.h"
#include "mongo/util/assert_util_core.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include <kmip.h>

namespace mongo::encryption::detail {
namespace {
const char* kmipErrorCodeToStr(int errorCode) {
    // @see the `KMIP_<smth>` constants in the beginning
    // of the `kmip.h` file
    switch (errorCode) {
        case KMIP_OK:
            return "not an error";
        case KMIP_NOT_IMPLEMENTED:
            return "not implemented";
        case KMIP_ERROR_BUFFER_FULL:
            return "buffer full";
        case KMIP_ERROR_ATTR_UNSUPPORTED:
            return "unsupported attribute";
        case KMIP_TAG_MISMATCH:
            return "tag mismatch";
        case KMIP_TYPE_MISMATCH:
            return "type mismatch";
        case KMIP_LENGTH_MISMATCH:
            return "length mismatch";
        case KMIP_PADDING_MISMATCH:
            return "padding mismatch";
        case KMIP_BOOLEAN_MISMATCH:
            return "boolean mismatch";
        case KMIP_ENUM_MISMATCH:
            return "enum mismatch";
        case KMIP_ENUM_UNSUPPORTED:
            return "enum unsupported";
        case KMIP_INVALID_FOR_VERSION:
            return "invalid for version";
        case KMIP_MEMORY_ALLOC_FAILED:
            return "memory allocation failed";
        case KMIP_IO_FAILURE:
            return "i/o failure";
        case KMIP_EXCEED_MAX_MESSAGE_SIZE:
            return "maximum message size is exceeded";
        case KMIP_MALFORMED_RESPONSE:
            return "malformed response";
        case KMIP_OBJECT_MISMATCH:
            return "object mismatch";
        case KMIP_ARG_INVALID:
            return "invalid argument";
        case KMIP_ERROR_BUFFER_UNDERFULL:
            return "buffer underfull";
        case KMIP_INVALID_ENCODING:
            return "invalid encoding";
        case KMIP_INVALID_FIELD:
            return "invalid field";
        case KMIP_INVALID_LENGTH:
            return "invalid length";
    }
    return nullptr;
}

const char* kmipServerStatusToStr(result_status serverStatus) {
    // @see the `result_status` enum in the `kmip.h` file
    switch (serverStatus) {
        case KMIP_STATUS_SUCCESS:
            return "operation succeeded";
        case KMIP_STATUS_OPERATION_FAILED:
            return "operation failed";
        case KMIP_STATUS_OPERATION_PENDING:
            return "operation pending";
        case KMIP_STATUS_OPERATION_UNDONE:
            return "operation undone";
    }
    return nullptr;
}

const char* kmipReasonToStr(result_reason reason) {
    // @see the `result_status` enum in the `kmip.h` file
    switch (reason) {
        case KMIP_REASON_GENERAL_FAILURE:
            return "General Failure";
        case KMIP_REASON_ITEM_NOT_FOUND:
            return "Item Not Found";
        case KMIP_REASON_RESPONSE_TOO_LARGE:
            return "Response Too Large";
        case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
            return "Authentication Not Successful";
        case KMIP_REASON_INVALID_MESSAGE:
            return "Invalid Message";
        case KMIP_REASON_OPERATION_NOT_SUPPORTED:
            return "Operation Not Supported";
        case KMIP_REASON_MISSING_DATA:
            return "Missing Data";
        case KMIP_REASON_INVALID_FIELD:
            return "Invalid Field";
        case KMIP_REASON_FEATURE_NOT_SUPPORTED:
            return "Feature Not Supported";
        case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
            return "Operation Canceled By Requester";
        case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
            return "Cryptographic Failure";
        case KMIP_REASON_ILLEGAL_OPERATION:
            return "Illegal Operation";
        case KMIP_REASON_PERMISSION_DENIED:
            return "Permission Denied";
        case KMIP_REASON_OBJECT_ARCHIVED:
            return "Object Archived";
        case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
            return "Index Out Of Bounds";
        case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
            return "Application Namespace Not Supported";
        case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
            return "Key Format Type Not Supported";
        case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
            return "Key Compression Type Not Supported";
        case KMIP_REASON_ENCODING_OPTION_FAILURE:
            return "Encoding Option Failure";
        case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
            return "Key Value Not Present";
        case KMIP_REASON_ATTESTATION_REQUIRED:
            return "Attestation Required";
        case KMIP_REASON_ATTESTATION_FAILED:
            return "Attestation Failed";
        case KMIP_REASON_SENSITIVE:
            return "Sensitive";
        case KMIP_REASON_NOT_EXTRACTABLE:
            return "Not Extractable";
        case KMIP_REASON_OBJECT_ALREADY_EXISTS:
            return "Object Already Exists";
        case KMIP_REASON_INVALID_TICKET:
            return "Invalid Ticket";
        case KMIP_REASON_USAGE_LIMIT_EXCEEDED:
            return "Usage Limit Exceeded";
        case KMIP_REASON_NUMERIC_RANGE:
            return "Numeric Range";
        case KMIP_REASON_INVALID_DATA_TYPE:
            return "Invalid Data Type";
        case KMIP_REASON_READ_ONLY_ATTRIBUTE:
            return "Read Only Attribute";
        case KMIP_REASON_MULTI_VALUED_ATTRIBUTE:
            return "Multi Valued Attribute";
        case KMIP_REASON_UNSUPPORTED_ATTRIBUTE:
            return "Unsupported Attribute";
        case KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND:
            return "Attribute Instance Not Found";
        case KMIP_REASON_ATTRIBUTE_NOT_FOUND:
            return "Attribute Not Found";
        case KMIP_REASON_ATTRIBUTE_READ_ONLY:
            return "Attribute Read Only";
        case KMIP_REASON_ATTRIBUTE_SINGLE_VALUED:
            return "Attribute Single Valued";
        case KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS:
            return "Bad Cryptographic Parameters";
        case KMIP_REASON_BAD_PASSWORD:
            return "Bad Password";
        case KMIP_REASON_CODEC_ERROR:
            return "Codec Error";
        case KMIP_REASON_ILLEGAL_OBJECT_TYPE:
            return "Illegal Object Type";
        case KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK:
            return "Incompatible Cryptographic Usage Mask";
        case KMIP_REASON_INTERNAL_SERVER_ERROR:
            return "Internal Server Error";
        case KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE:
            return "Invalid Asynchronous Correlation Value";
        case KMIP_REASON_INVALID_ATTRIBUTE:
            return "Invalid Attribute";
        case KMIP_REASON_INVALID_ATTRIBUTE_VALUE:
            return "Invalid Attribute Value";
        case KMIP_REASON_INVALID_CORRELATION_VALUE:
            return "Invalid Correlation Value";
        case KMIP_REASON_INVALID_CSR:
            return "Invalid CSR";
        case KMIP_REASON_INVALID_OBJECT_TYPE:
            return "Invalid Object Type";
        case KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED:
            return "Key Wrap Type Not Supported";
        case KMIP_REASON_MISSING_INITIALIZATION_VECTOR:
            return "Missing Initialization Vector";
        case KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE:
            return "Non Unique Name Attribute";
        case KMIP_REASON_OBJECT_DESTROYED:
            return "Object Destroyed";
        case KMIP_REASON_OBJECT_NOT_FOUND:
            return "Object Not Found";
        case KMIP_REASON_NOT_AUTHORISED:
            return "Not Authorised";
        case KMIP_REASON_SERVER_LIMIT_EXCEEDED:
            return "Server Limit Exceeded";
        case KMIP_REASON_UNKNOWN_ENUMERATION:
            return "Unknown Enumeration";
        case KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION:
            return "Unknown Message Extension";
        case KMIP_REASON_UNKNOWN_TAG:
            return "Unknown Tag";
        case KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS:
            return "Unsupported Cryptographic Parameters";
        case KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION:
            return "Unsupported Protocol Version";
        case KMIP_REASON_WRAPPING_OBJECT_ARCHIVED:
            return "Wrapping Object Archived";
        case KMIP_REASON_WRAPPING_OBJECT_DESTROYED:
            return "Wrapping Object Destroyed";
        case KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND:
            return "Wrapping Object Not Found";
        case KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE:
            return "Wrong Key Lifecycle State";
        case KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE:
            return "Protection Storage Unavailable";
        case KMIP_REASON_PKCS11_CODEC_ERROR:
            return "PKCS#11 Codec Error";
        case KMIP_REASON_PKCS11_INVALID_FUNCTION:
            return "PKCS#11 Invalid Function";
        case KMIP_REASON_PKCS11_INVALID_INTERFACE:
            return "PKCS#11 Invalid Interface";
        case KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE:
            return "Private Protection Storage Unavailable";
        case KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE:
            return "Public Protection Storage Unavailable";
    }
    return "Unknown";
}


std::string generateErrorMessage(int errorCode, const char* reason) {
    std::ostringstream msg;
    if (const char* error = kmipErrorCodeToStr(errorCode); error) {
        msg << error;
    } else {
        msg << "unknown error: error code " << errorCode;
    }
    if (reason) {
        msg << "; reason: " << reason;
    }
    return msg.str();
}

std::string generateErrorMessage(const ResponseBatchItem& respBatchItem) {
    std::ostringstream msg;
    if (const char* str = kmipServerStatusToStr(respBatchItem.result_status); str) {
        msg << "the KMIP server returned the '" << str << "' status";
    } else {
        msg << "the KMIP server returned unknown status code " << respBatchItem.result_status;
    }
    msg << "; reason: " << kmipReasonToStr(respBatchItem.result_reason);
    if (TextString* resMsg = respBatchItem.result_message; resMsg) {
        msg << "; message: " << std::string_view(resMsg->value, resMsg->size);
    }
    return msg.str();
}


class KmipExchangeError : public std::runtime_error {
public:
    KmipExchangeError(int errorCode, const char* reason = nullptr)
        : std::runtime_error(generateErrorMessage(errorCode, reason)) {}

    KmipExchangeError(const ResponseBatchItem& respBatchItem)
        : std::runtime_error(generateErrorMessage(respBatchItem)) {}
};

const char* kReasonOperationTypeMismatch = "operation type mismatch";
const char* kReasonObjectIdentifierMismatch = "object identifier mismatch";
}  // namespace

KmipExchange::KmipExchange() : _state(State::kNotStarted), _span(_buffer) {
    auto deleter = [](KMIP* ctx) {
        kmip_set_buffer(ctx, nullptr, 0);  // buffer is managed by a `SecureVector`
        kmip_destroy(ctx);
        delete ctx;
    };
    _ctx = std::shared_ptr<KMIP>(new KMIP(), deleter);
    kmip_init(_ctx.get(), nullptr, 0, KMIP_1_0);
}


void KmipExchange::state(State state) {
    switch (state) {
        case State::kNotStarted: {
            _state = state;
            _buffer->clear();
            return;
        }
        case State::kTransmittingRequest: {
            _state = state;
            _buffer->clear();
            encodeRequest();
            _span = Span(_ctx->buffer, _ctx->index - _ctx->buffer);
            return;
        }
        case State::kReceivingResponseLength: {
            _state = state;
            _buffer->resize(_kKmipTagTypeLengthSize, std::byte(0u));
            _span = Span(_buffer);
            return;
        }
        case State::kReceivingResponseValue: {
            invariant(_state == State::kReceivingResponseLength);
            _state = state;
            std::size_t valueLength = decodeValueLength();
            _buffer->resize(_kKmipTagTypeLengthSize + valueLength, std::byte(0u));
            _span = Span(_buffer->data() + _kKmipTagTypeLengthSize, valueLength);
            return;
        }
        case State::kResponseReceived: {
            invariant(_state == State::kReceivingResponseValue);
            _state = state;
            _span = Span(_buffer);
            return;
        }
    }
}

void KmipExchange::encodeRequestMessage(const RequestMessage& reqMsg) {
    auto encode = [this](std::size_t bufferBlockCount, const RequestMessage& reqMsg) {
        _buffer->resize(_kBufferBlockSize * bufferBlockCount, std::byte(0));
        kmip_set_buffer(_ctx.get(), _buffer->data(), _buffer->size());
        return kmip_encode_request_message(_ctx.get(), &reqMsg);
    };

    _buffer->clear();
    // @todo: tailor `bufferBlockCount` to maximum length of the used requests
    std::size_t bufferBlockCount = 1;
    int status = encode(bufferBlockCount, reqMsg);
    for (; status == KMIP_ERROR_BUFFER_FULL; status = encode(++bufferBlockCount, reqMsg)) {
    }
    if (status != KMIP_OK) {
        throw KmipExchangeError(status);
    }
}


std::size_t KmipExchange::decodeValueLength() const {
    invariant(_state == State::kReceivingResponseValue || _state == State::kResponseReceived);
    kmip_set_buffer(_ctx.get(), _buffer->data(), _buffer->size());
    _ctx->index += _kKmipTagTypeSize;
    std::uint32_t valueLength = 0;
    if (int status = kmip_decode_length(_ctx.get(), &valueLength); status != KMIP_OK) {
        throw KmipExchangeError(status);
    }
    if (valueLength > static_cast<std::size_t>(_ctx->max_message_size)) {
        throw KmipExchangeError(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    return static_cast<std::size_t>(valueLength);
}


std::shared_ptr<ResponseBatchItem> KmipExchange::decodeResponseBatchItem() {
    invariant(_state == State::kResponseReceived);

    auto deleter = [ctx = _ctx](ResponseMessage* respMsg) {
        kmip_free_response_message(ctx.get(), respMsg);
    };
    std::shared_ptr<ResponseMessage> respMsg(new ResponseMessage(), std::move(deleter));
    kmip_set_buffer(_ctx.get(), _buffer->data(), _buffer->size());
    if (int status = kmip_decode_response_message(_ctx.get(), respMsg.get()); status != KMIP_OK) {
        throw KmipExchangeError(status);
    }

    if (respMsg->batch_count != 1 || respMsg->batch_items == nullptr) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE,
                                "unexpected batch item count or no batch item");
    }
    std::shared_ptr<ResponseBatchItem> respBatchItem(respMsg, &respMsg->batch_items[0]);

    return respBatchItem;
}


void KmipExchangeRegisterSymmetricKey::encodeRequest() {
    invariant(_state == State::kTransmittingRequest);

    auto protoVersion = ProtocolVersion();
    kmip_init_protocol_version(&protoVersion, _ctx->version);

    auto reqHeader = RequestHeader();
    kmip_init_request_header(&reqHeader);
    reqHeader.protocol_version = &protoVersion;
    reqHeader.maximum_response_size = _ctx->max_message_size;
    reqHeader.time_stamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    reqHeader.batch_count = 1;

    std::array<Attribute, 3> attrs;
    for (std::size_t i = 0; i < attrs.size(); i++) {
        kmip_init_attribute(&attrs[i]);
    }

    enum cryptographic_algorithm algo = KMIP_CRYPTOALG_AES;
    attrs[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    attrs[0].value = &algo;

    int32 length = _key.size() * 8;
    attrs[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    attrs[1].value = &length;

    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    attrs[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    attrs[2].value = &mask;

    auto templAttr = TemplateAttribute();
    templAttr.attributes = attrs.data();
    templAttr.attribute_count = attrs.size();

    auto regReqPayload = RegisterRequestPayload();
    regReqPayload.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    regReqPayload.template_attribute = &templAttr;

    auto keyBlock = KeyBlock();
    regReqPayload.object.key_block = &keyBlock;
    kmip_init_key_block(regReqPayload.object.key_block);
    regReqPayload.object.key_block->key_format_type = KMIP_KEYFORMAT_RAW;

    auto byteStr = ByteString();
    byteStr.value = reinterpret_cast<uint8*>(const_cast<std::byte*>(_key.data()));
    byteStr.size = _key.size();

    auto keyValue = KeyValue();
    keyValue.key_material = &byteStr;
    keyValue.attribute_count = 0;
    keyValue.attributes = nullptr;

    regReqPayload.object.key_block->key_value = &keyValue;
    regReqPayload.object.key_block->key_value_type = KMIP_TYPE_BYTE_STRING;
    regReqPayload.object.key_block->cryptographic_algorithm = KMIP_CRYPTOALG_AES;
    regReqPayload.object.key_block->cryptographic_length = _key.size() * 8;

    auto reqBatchItem = RequestBatchItem();
    kmip_init_request_batch_item(&reqBatchItem);
    reqBatchItem.operation = KMIP_OP_REGISTER;
    reqBatchItem.request_payload = &regReqPayload;

    auto reqMsg = RequestMessage();
    reqMsg.request_header = &reqHeader;
    reqMsg.batch_items = &reqBatchItem;
    reqMsg.batch_count = 1;

    encodeRequestMessage(reqMsg);
}


std::string KmipExchangeRegisterSymmetricKey::decodeKeyId() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_REGISTER) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonOperationTypeMismatch);
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw KmipExchangeError(*respBatchItem.get());
    }

    auto* respPayload = reinterpret_cast<RegisterResponsePayload*>(respBatchItem->response_payload);
    TextString* id = respPayload->unique_identifier;
    return id && id->value
        ? std::string(id->value, id->size)
        : throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonObjectIdentifierMismatch);
}

void KmipExchangeActivate::encodeRequest() {
    invariant(_state == State::kTransmittingRequest);

    auto protoVersion = ProtocolVersion();
    kmip_init_protocol_version(&protoVersion, _ctx->version);

    auto reqHeader = RequestHeader();
    kmip_init_request_header(&reqHeader);
    reqHeader.protocol_version = &protoVersion;
    reqHeader.maximum_response_size = _ctx->max_message_size;
    reqHeader.time_stamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    reqHeader.batch_count = 1;

    auto uid = TextString();
    uid.value = const_cast<char*>(_keyId.data());
    uid.size = _keyId.size();

    auto reqPayload = ActivateRequestPayload();
    reqPayload.unique_identifier = &uid;

    auto reqBatchItem = RequestBatchItem();
    kmip_init_request_batch_item(&reqBatchItem);
    reqBatchItem.operation = KMIP_OP_ACTIVATE;
    reqBatchItem.request_payload = &reqPayload;

    auto reqMsg = RequestMessage();
    reqMsg.request_header = &reqHeader;
    reqMsg.batch_items = &reqBatchItem;
    reqMsg.batch_count = 1;

    encodeRequestMessage(reqMsg);
}

void KmipExchangeActivate::verifyResponse() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_ACTIVATE) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonOperationTypeMismatch);
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw KmipExchangeError(*respBatchItem.get());
    }

    auto* respPayload = reinterpret_cast<ActivateResponsePayload*>(respBatchItem->response_payload);
    auto uid = respPayload->unique_identifier;
    if (std::string_view(uid->value, uid->size) != _keyId) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonObjectIdentifierMismatch);
    }
}

void KmipExchangeGetSymmetricKey::encodeRequest() {
    invariant(_state == State::kTransmittingRequest);

    auto protoVersion = ProtocolVersion();
    kmip_init_protocol_version(&protoVersion, _ctx->version);

    auto reqHeader = RequestHeader();
    kmip_init_request_header(&reqHeader);
    reqHeader.protocol_version = &protoVersion;
    reqHeader.maximum_response_size = _ctx->max_message_size;
    reqHeader.time_stamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    reqHeader.batch_count = 1;

    auto uid = TextString();
    uid.value = const_cast<char*>(_keyId.data());
    uid.size = _keyId.size();

    auto getReqPayload = GetRequestPayload();
    getReqPayload.unique_identifier = &uid;

    auto reqBatchItem = RequestBatchItem();
    kmip_init_request_batch_item(&reqBatchItem);
    reqBatchItem.operation = KMIP_OP_GET;
    reqBatchItem.request_payload = &getReqPayload;

    auto reqMsg = RequestMessage();
    reqMsg.request_header = &reqHeader;
    reqMsg.batch_items = &reqBatchItem;
    reqMsg.batch_count = 1;

    encodeRequestMessage(reqMsg);
}

boost::optional<Key> KmipExchangeGetSymmetricKey::decodeKey() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_GET) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonOperationTypeMismatch);
    }
    if (respBatchItem->result_status == KMIP_STATUS_OPERATION_FAILED &&
        respBatchItem->result_reason == KMIP_REASON_ITEM_NOT_FOUND) {
        return {};
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw KmipExchangeError(*respBatchItem.get());
    }

    auto* respPayload = reinterpret_cast<GetResponsePayload*>(respBatchItem->response_payload);
    auto uid = respPayload->unique_identifier;
    if (std::string_view(uid->value, uid->size) != _keyId) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonObjectIdentifierMismatch);
    }
    if (respPayload->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY) {
        throw KmipExchangeError(KMIP_OBJECT_MISMATCH, "object type mismatch");
    }
    auto* symmetricKey = reinterpret_cast<SymmetricKey*>(respPayload->object);
    KeyBlock* keyBlock = symmetricKey->key_block;
    if (keyBlock->key_format_type != KMIP_KEYFORMAT_RAW) {
        throw KmipExchangeError(KMIP_OBJECT_MISMATCH, "key format type mismatch");
    }
    if (keyBlock->key_wrapping_data != nullptr) {
        throw KmipExchangeError(KMIP_OBJECT_MISMATCH, "unexpected wrapped key");
    }
    auto* keyValue = reinterpret_cast<KeyValue*>(keyBlock->key_value);
    auto* material = reinterpret_cast<ByteString*>(keyValue->key_material);
    return Key(reinterpret_cast<std::byte*>(material->value), material->size);
}

void KmipExchangeGetKeyState::encodeRequest() {
    invariant(_state == State::kTransmittingRequest);

    auto protoVersion = ProtocolVersion();
    kmip_init_protocol_version(&protoVersion, _ctx->version);

    auto reqHeader = RequestHeader();
    kmip_init_request_header(&reqHeader);
    reqHeader.protocol_version = &protoVersion;
    reqHeader.maximum_response_size = _ctx->max_message_size;
    reqHeader.time_stamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    reqHeader.batch_count = 1;

    auto uid = TextString();
    uid.value = const_cast<char*>(_keyId.data());
    uid.size = _keyId.size();

    static constexpr const char* kState = "State";
    auto attrName = TextString();
    attrName.value = const_cast<char*>(kState);
    attrName.size = std::strlen(kState);

    auto getAttrReqPayload = GetAttributesRequestPayload();
    getAttrReqPayload.unique_identifier = &uid;
    getAttrReqPayload.attribute_name = &attrName;

    auto reqBatchItem = RequestBatchItem();
    kmip_init_request_batch_item(&reqBatchItem);
    reqBatchItem.operation = KMIP_OP_GET_ATTRIBUTES;
    reqBatchItem.request_payload = &getAttrReqPayload;

    auto reqMsg = RequestMessage();
    reqMsg.request_header = &reqHeader;
    reqMsg.batch_items = &reqBatchItem;
    reqMsg.batch_count = 1;

    encodeRequestMessage(reqMsg);
}

boost::optional<KeyState> KmipExchangeGetKeyState::decodeKeyState() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_GET_ATTRIBUTES) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonOperationTypeMismatch);
    }
    if (respBatchItem->result_status == KMIP_STATUS_OPERATION_FAILED &&
        respBatchItem->result_reason == KMIP_REASON_ITEM_NOT_FOUND) {
        return boost::none;
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw KmipExchangeError(*respBatchItem.get());
    }

    auto* respPayload =
        reinterpret_cast<GetAttributesResponsePayload*>(respBatchItem->response_payload);
    TextString* id = respPayload->unique_identifier;
    if (std::string_view(id->value, id->size) != _keyId) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, kReasonObjectIdentifierMismatch);
    }
    if (respPayload->attribute->type != KMIP_ATTR_STATE) {
        throw KmipExchangeError(KMIP_MALFORMED_RESPONSE, "attribute type mismatch");
    }
    enum state s = *reinterpret_cast<enum state*>(respPayload->attribute->value);
    switch (s) {
        case KMIP_STATE_PRE_ACTIVE:
            return KeyState::kPreActive;
        case KMIP_STATE_ACTIVE:
            return KeyState::kActive;
        case KMIP_STATE_DEACTIVATED:
            return KeyState::kDeactivated;
        case KMIP_STATE_COMPROMISED:
            return KeyState::kCompromised;
        case KMIP_STATE_DESTROYED:
            return KeyState::kDestroyed;
        case KMIP_STATE_DESTROYED_COMPROMISED:
            return KeyState::kDestroyedCompromised;
    }
    // hanlde extension values
    return KeyState(static_cast<std::underlying_type_t<enum state>>(s));
}

}  // namespace mongo::encryption::detail
