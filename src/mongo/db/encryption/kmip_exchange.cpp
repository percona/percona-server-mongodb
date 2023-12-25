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

#include <array>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string_view>
#include <type_traits>

#include <kmip_bio.h>
#include <kmippp/kmippp.h>

#include "mongo/db/encryption/key.h"
#include "mongo/util/assert_util_core.h"

namespace mongo::encryption::detail {
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
        throw kmippp::operation_error(status, kmip_get_last_result());
    }
}


std::size_t KmipExchange::decodeValueLength() const {
    invariant(_state == State::kReceivingResponseValue || _state == State::kResponseReceived);
    kmip_set_buffer(_ctx.get(), _buffer->data(), _buffer->size());
    _ctx->index += _kKmipTagTypeSize;
    std::uint32_t valueLength = 0;
    if (int status = kmip_decode_length(_ctx.get(), &valueLength); status != KMIP_OK) {
        throw kmippp::operation_error(status, kmip_get_last_result());
    }
    if (valueLength > static_cast<std::size_t>(_ctx->max_message_size)) {
        throw kmippp::operation_error(KMIP_EXCEED_MAX_MESSAGE_SIZE, kmip_get_last_result());
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
        throw kmippp::operation_error(status, kmip_get_last_result());
    }

    if (respMsg->batch_count != 1 || respMsg->batch_items == nullptr) {
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
    }
    std::shared_ptr<ResponseBatchItem> respBatchItem(respMsg, &respMsg->batch_items[0]);
    kmip_set_last_result(respBatchItem.get());

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
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw kmippp::operation_error(respBatchItem->result_status, kmip_get_last_result());
    }

    auto* respPayload = reinterpret_cast<RegisterResponsePayload*>(respBatchItem->response_payload);
    TextString* id = respPayload->unique_identifier;
    kmip_clear_last_result();
    return id && id->value
        ? std::string(id->value, id->size)
        : throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
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
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw kmippp::operation_error(respBatchItem->result_status, kmip_get_last_result());
    }

    auto* respPayload = reinterpret_cast<ActivateResponsePayload*>(respBatchItem->response_payload);
    auto uid = respPayload->unique_identifier;
    if (std::string_view(uid->value, uid->size) != _keyId) {
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
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

std::optional<Key> KmipExchangeGetSymmetricKey::decodeKey() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_GET) {
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
    }
    if (respBatchItem->result_status == KMIP_STATUS_OPERATION_FAILED &&
        respBatchItem->result_reason == KMIP_REASON_ITEM_NOT_FOUND) {
        return {};
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw kmippp::operation_error(respBatchItem->result_status, kmip_get_last_result());
    }

    auto* respPayload = reinterpret_cast<GetResponsePayload*>(respBatchItem->response_payload);
    if (respPayload->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY) {
        throw kmippp::operation_error(KMIP_OBJECT_MISMATCH, kmip_get_last_result());
    }
    auto* symmetricKey = reinterpret_cast<SymmetricKey*>(respPayload->object);
    KeyBlock* keyBlock = symmetricKey->key_block;
    if ((keyBlock->key_format_type != KMIP_KEYFORMAT_RAW) ||
        (keyBlock->key_wrapping_data != nullptr)) {
        throw kmippp::operation_error(KMIP_OBJECT_MISMATCH, kmip_get_last_result());
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

    auto getAttrReqPayload = GetAttributeRequestPayload();
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

std::optional<KeyState> KmipExchangeGetKeyState::decodeKeyState() {
    invariant(_state == State::kResponseReceived);

    auto respBatchItem = decodeResponseBatchItem();
    if (respBatchItem->operation != KMIP_OP_GET_ATTRIBUTES) {
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
    }
    if (respBatchItem->result_status == KMIP_STATUS_OPERATION_FAILED &&
        respBatchItem->result_reason == KMIP_REASON_ITEM_NOT_FOUND) {
        return std::nullopt;
    }
    if (respBatchItem->result_status != KMIP_STATUS_SUCCESS) {
        throw kmippp::operation_error(respBatchItem->result_status, kmip_get_last_result());
    }

    auto* respPayload =
        reinterpret_cast<GetAttributeResponsePayload*>(respBatchItem->response_payload);
    TextString* id = respPayload->unique_identifier;
    if (std::string_view(id->value, id->size) != _keyId ||
        respPayload->attribute->type != KMIP_ATTR_STATE) {
        throw kmippp::operation_error(KMIP_MALFORMED_RESPONSE, kmip_get_last_result());
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
