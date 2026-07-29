/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_f.cpp
  @brief Emulation layer for NFC-F
*/
#include "emulation_layer_f.hpp"
#include "nfc/a/nfca.hpp"
#include <M5Utility.hpp>
#include <M5Unified.h>

using namespace m5::nfc;
using namespace m5::nfc::f;

// clang-format off
#pragma GCC optimize("O3")
// clang-format on

namespace {

constexpr uint32_t rc_offset       = 16u * (lite_s::REG.number + 1);
constexpr uint32_t wcnt_offset     = rc_offset + 16u * 9;
constexpr uint32_t crc_ceck_offset = wcnt_offset + 16u * 3;
constexpr uint8_t null_data[16]{};

uint8_t* block_to_address(uint8_t* mem, const uint32_t mem_size, const uint16_t block)
{
    if (!mem || !mem_size) {
        return nullptr;
    }

    uint32_t offset{mem_size};

    if (block <= lite_s::REG.number) {  // 0x00 - 0x0D
        offset = 16 * block;
    } else if (block <= lite_s::MC.number) {  // 0x80 - 0x88
        offset = rc_offset + 16 * (block - lite_s::RC.number);
    } else if (block <= lite_s::STATE.number) {  // 0x90 - 0x92
        offset = wcnt_offset + 16 * (block - lite_s::WCNT.number);
    } else if (block == lite_s::CRC_CHECK.number) {
        offset = crc_ceck_offset;
    }
    return (offset + 16 <= mem_size) ? (mem + offset) : nullptr;
}

inline bool is_system_code_ndef(const uint8_t sc[2])
{
    return sc && sc[0] == 0x12 && sc[1] == 0xFC;
}

inline bool is_system_code_lite(const uint8_t sc[2])
{
    return sc && sc[0] == 0x88 && sc[1] == 0xB4;
}

inline bool is_system_code_wildcard(const uint8_t sc[2])
{
    return sc && sc[0] == 0xFF && sc[1] == 0xFF;
}

inline bool is_system_code_match(const uint8_t poll_sc[2], const uint16_t sc){
    const bool msb_match = (poll_sc[0] == 0xff) || (poll_sc[0] == ((sc >> 8) & 0xff));
    const bool lsb_match = (poll_sc[1] == 0xff) || (poll_sc[1] == (sc & 0xff));

    return msb_match && lsb_match;
}
}  // namespace

namespace m5 {
namespace nfc {

EmulationLayerF::~EmulationLayerF() = default;

bool EmulationLayerF::begin(const m5::nfc::f::PICC& picc, uint8_t* ptr, const uint32_t size,
                            const uint8_t idi[8],
                            const uint8_t pmi[8],
                            const DesKey &system_key,
                            const std::vector<Area> &areas,
                            const std::vector<Service> &services,
                            void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*),
                            const bool auto_res, const bool listen_any)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
        return false;
    }

    /*
    if (!(picc.isNTAG() || picc.type == Type::MIFARE_Ultralight)) {
        M5_LIB_LOGE("Not support %u %s", picc.type, picc.typeAsString().c_str());
        return false;
    }
    */

    _picc        = picc;
    _memory      = ptr;
    _memory_size = size;
    _callback    = callback;

    if(idi != nullptr){
        memcpy(this->idi, idi, 8);
    }
    if(pmi != nullptr){
        memcpy(this->pmi, pmi, 8);
    }

    memcpy(this->_system_key.key, system_key.key, 8);
    _system_key.version = system_key.version;

    _areas = areas;
    _services = services;

    if(_areas.size() == 0){
        return false;
    }
    if(_areas[0].area_code != 0x0000){
        return false;
    }
    if(_areas[0].end_service_code != 0xFFFE){
        return false;
    }

    std::sort(_areas.begin(), _areas.end());
    std::sort(_services.begin(), _services.end());

    for(uint16_t i = 0; i < _areas.size(); i++){
        if(!FeliCaStandard::is_area_code(_areas[i].area_code)){
            return false;
        }
        if(0 < i && _areas[i - 1].area_code == _areas[i].area_code){
            return false;
        }
    }
    for(uint16_t i = 0; i < _services.size(); i++){
        if(!FeliCaStandard::is_service_code(_services[i].service_code)){
            return false;
        }
        if(0 < i && _services[i - 1].service_code == _services[i].service_code){
            return false;
        }
    }

    /*
    if (!_picc.valid() || !_memory || _memory_size < _picc.totalSize()) {
        M5_LIB_LOGE("Invalid picc setting %s:%s %p %u/%u",  //
                    picc.uidAsString().c_str(), picc.typeAsString().c_str(), _memory, _memory_size, _picc.totalSize());
        return false;
    }
    */

    _state = _impl->start_emulation(_picc, auto_res, listen_any) ? State::Off : State::None;
    _prev  = State::None;

    _expired_at = m5::utility::millis() + _expired_ms;
    return (_state != State::None);
}

bool EmulationLayerF::end()
{
    if (_state == State::None) {
        return true;
    }
    _state = State::None;
    return _impl->stop_emulation();
}

void EmulationLayerF::update()
{
    auto save = _state;
    //    if (_state != _prev) {
    //        _expired_at = m5::utility::millis() + _expired_ms; // IRQ byGT ???
    //    }

    switch (_state) {
        case State::None:
            break;
        case State::Off:
            //            if (_state != _prev) M5_LIB_LOGE("==OFF");
            update_off();
            break;
        case State::Communicated:
            //            if (_state != _prev) M5_LIB_LOGE("==COMM");
            update_communicated();
            break;
        case State::Selected:
            //            if (_state != _prev) M5_LIB_LOGE("==SEL");
            update_selected();
            break;
        default:
            break;
    }
    _prev = save;
}

void EmulationLayerF::update_off()
{
    _state = _impl->update_off();
}

void EmulationLayerF::update_communicated()
{
    _state = _impl->update_communicated();
}

void EmulationLayerF::update_selected()
{
    _state = _impl->update_selected();
}

uint16_t EmulationLayerF::find_area(const uint16_t area_code){
    if(!f::FeliCaStandard::is_area_code(area_code)){
        return 0xffff;
    }

    const auto it = std::find(this->_areas.begin(), this->_areas.end(), area_code);
    if(it == this->_areas.end()){
        return 0xffff;
    }

    return std::distance(this->_areas.begin(), it);
}
uint16_t EmulationLayerF::find_service(const uint16_t service_code){
    if(!f::FeliCaStandard::is_service_code(service_code)){
        return 0xffff;
    }

    const auto it = std::find(this->_services.begin(), this->_services.end(), service_code);
    if(it == this->_services.end()){
        return 0xffff;
    }

    return std::distance(this->_services.begin(), it);
}


EmulationLayerF::State EmulationLayerF::receive_standard_callback_plain(const State s, const uint8_t* rx, const uint32_t rx_len){
    if(this->_picc.type != Type::FeliCaStandard){
        return s;
    }
    if(rx_len < 10){
        return s;
    }
    if(memcmp(_picc.idm, rx + 2, sizeof(_picc.idm)) != 0){
        return s;
    }

    State ret = s;

    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::Authentication1: {
            if(rx_len < 10 + 1 + 2 + 1 + 2 + 8){
                break;
            }
            uint16_t offset = 10;
            const uint8_t area_code_count = rx[offset++];
            if(area_code_count == 0 || 16 < area_code_count){
                break;
            }
            if(rx_len < offset + (2 * area_code_count) + 1 + 2 + 8){
                break;
            }
            const uint8_t* area_code_list = rx + offset;
            offset += (2 * area_code_count);

            const uint8_t service_code_count = rx[offset++];
            if(service_code_count == 0 || 16 < service_code_count){
                break;
            }
            if(rx_len != offset + (2 * service_code_count) + 8){
                break;
            }
            const uint8_t* service_code_list = rx + offset;
            offset += (2 * service_code_count);

            uint8_t* area_keys[16];
            for(uint8_t i = 0; i < area_code_count; i++){
                const uint16_t area_code = ((uint16_t)*(area_code_list + (i * 2))) | (((uint16_t)*(area_code_list + (i * 2) + 1)) << 8);

                if(area_code == 0xffff){
                    area_keys[i] = this->_system_key.key;
                }
                else if(FeliCaStandard::is_area_code(area_code)){
                    const uint16_t index = find_area(area_code);
                    if(index == 0xffff){
                        return s;
                    }
                    area_keys[i] = this->_areas[index].key.key;
                }
                else if(FeliCaStandard::is_service_code(area_code)){
                    if(FeliCaStandard::is_auth_required(area_code)){
                        const uint16_t index = find_service(area_code);
                        if(index == 0xffff){
                            return s;
                        }
                        area_keys[i] = this->_services[index].key.key;
                    }
                    else{
                        area_keys[i] = nullptr;
                    }
                }
            }


            uint8_t* service_keys[16];
            for(uint8_t i = 0; i < service_code_count; i++){
                const uint16_t service_code = ((uint16_t)*(service_code_list + (i * 2))) | (((uint16_t)*(service_code_list + (i * 2) + 1)) << 8);

                if(service_code == 0xffff){
                    service_keys[i] = this->_system_key.key;
                }
                else if(FeliCaStandard::is_area_code(service_code)){
                    const uint16_t index = find_area(service_code);
                    if(index == 0xffff){
                        return s;
                    }
                    service_keys[i] = this->_areas[index].key.key;
                }
                else if(FeliCaStandard::is_service_code(service_code)){
                    if(FeliCaStandard::is_auth_required(service_code)){
                        const uint16_t index = find_service(service_code);
                        if(index == 0xffff){
                            return s;
                        }
                        service_keys[i] = this->_services[index].key.key;
                    }
                    else{
                        service_keys[i] = nullptr;
                    }
                }
            }

            this->_mode = 1;
            
            for(uint8_t i = 0; i < service_code_count; i++){
                this->_auth_state.services[i] = ((uint16_t)*(service_code_list + (i * 2))) | (((uint16_t)*(service_code_list + (i * 2) + 1)) << 8);
            }
            this->_auth_state.service_count = service_code_count;

            uint8_t gsk[8];
            uint8_t usk[8];
            FeliCaStandard::generate_groupkey(this->_system_key.key, area_code_count, area_keys, service_code_count, service_keys, gsk, usk);

            for(uint8_t i = 0; i < 8; i++){
                gsk[i] ^= this->_picc.idm[i];
            }
            this->_auth_state.key_l = crypto::des::load64_be(gsk);
            crypto::des::des_ctx_t ctx_l;
            crypto::des::des_set_key_uint64(&ctx_l, this->_auth_state.key_l);

            crypto::des::des_encrypt(&ctx_l, usk, usk);
            this->_auth_state.key_alpha = crypto::des::load64_be(usk);
            crypto::des::des_ctx_t ctx_alpha;
            crypto::des::des_set_key_uint64(&ctx_alpha, this->_auth_state.key_alpha);

            crypto::des::des_encrypt(&ctx_alpha, gsk, gsk);
            crypto::des::des_ctx_t ctx_beta;
            crypto::des::des_set_key_uint64(&ctx_beta, crypto::des::load64_be(gsk));

            // generate transaction key
            const auto high = esp_random();
            const auto low  = esp_random();
            this->_auth_state.transaction_key = ((uint64_t)high << 32) | low;

            uint64_t transaction_id = crypto::des::load64_be(rx + offset);
            transaction_id = crypto::des::tdes_decrypt_uint64(&ctx_alpha, &ctx_l, &ctx_alpha, transaction_id);
            crypto::des::store64_be(transaction_id, this->_auth_state.transaction_id);
            
            transaction_id = crypto::des::tdes_encrypt_uint64(&ctx_l, &ctx_beta, &ctx_l, transaction_id);

            uint64_t challenge_2 = crypto::des::tdes_encrypt_uint64(&ctx_l, &ctx_beta, &ctx_l, this->_auth_state.transaction_key);

            offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 8 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::Authentication1);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;

            crypto::des::store64_be(transaction_id, tx.data() + offset);
            offset += 8;
            crypto::des::store64_be(challenge_2, tx.data() + offset);
            offset += 8;

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::Authentication2: {
            if(this->_mode != 1){
                break;
            }

            if(rx_len < 10 + 8){
                break;
            }

            uint64_t transaction_key = crypto::des::load64_be(rx + 10);

            crypto::des::des_ctx_t ctx_l;
            crypto::des::des_set_key_uint64(&ctx_l, this->_auth_state.key_l);

            crypto::des::des_ctx_t ctx;
            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.key_alpha);

            transaction_key = crypto::des::tdes_decrypt_uint64(&ctx, &ctx_l, &ctx, transaction_key);
            if(transaction_key != this->_auth_state.transaction_key){
                break;
            }

            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 8 + 8 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::Authentication2);
            
            this->_auth_state.transaction_count = 0;

            tx[offset++] = this->_auth_state.transaction_count & 0xff;
            tx[offset++] = (this->_auth_state.transaction_count >> 8) & 0xff;
            memcpy(tx.data() + offset, this->_auth_state.transaction_id + 2, 6);
            offset += 6;

            memcpy(tx.data() + offset, this->idi, 8);
            offset += 8;

            memcpy(tx.data() + offset, this->pmi, 8);
            offset += 8;

            FeliCaStandard::calculate_mac(tx[0], tx.data() + 1, 8 + 8 + 8, tx.data() + offset);
            offset += 8;

            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);
            crypto::des::des_cbc_encrypt(&ctx, tx.data() + 1, tx.data() + 1, 8 + 8 + 8 + 8);

            this->_mode = 2;

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }

        case CommandCode::RequestService: {
            if(rx_len < 10 + 1 + 2){
                break;
            }

            const uint8_t node_count = rx[10];
            if((node_count < 1 || 32 < node_count) || rx_len != 10 + 1 + 2 * node_count){
                break;
            }

            const uint8_t* node_code_list = rx + 11;

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 1 + 2 * node_count);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::RequestService);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;

            tx[offset++] = node_count;
            for(uint8_t i = 0; i < node_count; i++){
                const uint16_t node_code = ((uint16_t)*(node_code_list + (i * 2))) | (((uint16_t)*(node_code_list + (i * 2) + 1)) << 8);
                uint16_t key_version;

                if(node_code == 0xffff){
                    key_version = this->_system_key.version;
                }
                else if(FeliCaStandard::is_area_code(node_code)){
                    const uint16_t index = find_area(node_code);
                    if(index == 0xffff){
                        key_version = 0xffff;
                    }
                    else{
                        key_version = this->_areas[index].key.version;
                    }
                }
                else if(FeliCaStandard::is_service_code(node_code)){
                    const uint16_t index = find_service(node_code);
                    if(index == 0xffff){
                        key_version = 0xffff;
                    }
                    else{
                        key_version = this->_services[index].key.version;
                    }
                }

                tx[offset + i * 2] = key_version & 0xff;
                tx[offset + i * 2 + 1] = (key_version >> 8) & 0xff;
            }

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::RequestResponse: {
            if(rx_len != 10){
                break;
            }

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 1);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::RequestResponse);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;
            tx[offset++] = this->_mode;

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::SearchServiceCode: {
            if(rx_len != 10 + 2){
                break;
            }

            const uint16_t node_index = (((uint16_t)rx[11]) << 8) | rx[10];

            uint16_t node_code;
            uint16_t end_service_code = 0xffff;
            if(node_index < this->_areas.size()){
                node_code = this->_areas[node_index].area_code;
                end_service_code = this->_areas[node_index].end_service_code;
            }
            else if(node_index < this->_areas.size() + this->_services.size()){
                node_code = this->_services[node_index - this->_areas.size()].service_code;
            }
            else{
                node_code = 0xffff;
            }

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};

            if(f::FeliCaStandard::is_area_code(node_code)){
                tx.resize(1 + 8 + 4);
            }
            else{
                tx.resize(1 + 8 + 2);
            }

            tx[offset++] = m5::stl::to_underlying(ResponseCode::SearchServiceCode);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;
            tx[offset++] = node_code & 0xff;
            tx[offset++] = (node_code >> 8) & 0xff;
            if(f::FeliCaStandard::is_area_code(node_code)){
                tx[offset++] = end_service_code & 0xff;
                tx[offset++] = (end_service_code >> 8) & 0xff;
            }

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::RequestSystemCode: {
            if(rx_len != 10){
                break;
            }

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 1 + 2);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::RequestSystemCode);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;
            tx[offset++] = 1;
            
            tx[offset++] = (this->_picc.emulation_sc >> 8) & 0xff;
            tx[offset++] = this->_picc.emulation_sc & 0xff;

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::ResetMode: {
            if(rx_len != 12){
                break;
            }

            this->_mode = 0x00;

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8 + 2);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::ResetMode);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;
            tx[offset++] = 0x00;
            tx[offset++] = 0x00;

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;
        }
        case CommandCode::ReadWithoutEncryption: {
            if(this->_mode != 0){
                break;
            }
            if(rx_len < 10 + 1 + 2 + 1 + 2){
                break;
            }

            uint16_t offset = 0;
            std::vector<uint8_t> tx{};
            tx.resize(1 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption);
            memcpy(tx.data() + offset, _picc.idm, 8);
            offset += 8;

            const uint8_t service_count = rx[10];
            if(service_count < 1 || 16 < service_count){
                tx.resize(1 + 8 + 2);
                tx[offset++] = 0xff;
                tx[offset++] = 0xa1;

                ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
                break;
            }
            if(rx_len < 10 + 1 + (2 * service_count) + 1 + 2){
                break;
            }
            const uint8_t* service_list = rx + 10 + 1;

            const uint8_t block_count = rx[10 + 1 + (2 * service_count)];
            if(block_count < 1 || 255 < (10 + 2 + 1 + (16 * block_count))){
                tx.resize(1 + 8 + 2);
                tx[offset++] = 0xff;
                tx[offset++] = 0xa2;

                ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
                break;
            }
            if(rx_len < 10 + 1 + (2 * service_count) + 1 + (2 * block_count)){
                break;
            }

            uint8_t block_offset = 10 + 1 + (2 * service_count) + 1;
            uint16_t error = 0x0000;

            tx.resize(1 + 8 + 2 + 1 + (16 * block_count));

            tx[offset++] = 0x00;
            tx[offset++] = 0x00;
            tx[offset++] = block_count;

            for (uint8_t i = 0; i < block_count; i++) {
                const block_t b = block_t::from(rx + block_offset);
                block_offset += 2 + b.is_3byte();

                if(b.access_mode() != 0b000){
                    error = ((i + 1) << 8) | 0xA7;
                    break;
                }

                const uint8_t order = b.order();
                if(service_count <= order){
                    error = ((i + 1) << 8) | 0xA3;
                    break;
                }

                const uint16_t service_code = service_list[order * 2] | (((uint16_t)service_list[(order * 2) + 1]) << 8);
                if(!f::FeliCaStandard::is_service_code(service_code)){
                    error = ((i + 1) << 8) | 0xA4;
                    break;
                }
                if(f::FeliCaStandard::is_auth_required(service_code)){
                    error = ((i + 1) << 8) | 0xA5;
                    break;
                }

                const uint16_t service_index = find_service(service_code);
                if(service_index == 0xffff){
                    error = ((i + 1) << 8) | 0xA6;
                    break;
                }
                const auto service = this->_services[service_index];

                if(service.block_count <= b.block()){
                    error = ((i + 1) << 8) | 0xA8;
                    break;
                }

                if(service.service_block == nullptr){
                    memset(tx.data() + offset, 0x00, 16);
                }
                else {
                    memcpy(tx.data() + offset, service.service_block + (b.block() * 16), 16);
                }

                offset += 16;
            }

            if(error != 0x0000){
                tx.resize(1 + 8 + 2);
                tx[9] = error >> 8;
                tx[10] = error & 0xff;
            }

            ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            break;

        }
        case CommandCode::WriteWithoutEncryption:
            break;
    }

    return ret;
}
EmulationLayerF::State EmulationLayerF::receive_standard_callback_secure(const State s, const uint8_t* rx, const uint32_t rx_len){
    if(this->_picc.type != Type::FeliCaStandard){
        return s;
    }
    if(rx_len < 18 || (rx_len - 2) % 8 != 0){
        return s;
    }
    if(!(this->_mode == 2 || this->_mode == 3)){
        return s;
    }
    if(this->_auth_state.transaction_count == 0xffff){
        return s;
    }

    std::vector<uint8_t> plain_rx(rx_len - 2);

    crypto::des::des_ctx_t ctx;
    crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);
    crypto::des::des_cbc_decrypt(&ctx, rx + 2, plain_rx.data(), plain_rx.size());

    const uint16_t transaction_count = plain_rx[0] | (((uint16_t)plain_rx[1]) << 8);
    if(transaction_count <= this->_auth_state.transaction_count){
        return s;
    }
    if(std::memcmp(plain_rx.data() + 2, this->_auth_state.transaction_id + 2, 6) != 0){
        return s;
    }

    std::vector<uint8_t> calculated_mac(8);
    f::FeliCaStandard::calculate_mac(rx[1], plain_rx.data(), plain_rx.size() - 8, calculated_mac.data());
    if(std::memcmp(plain_rx.data() + plain_rx.size() - 8, calculated_mac.data(), 8) != 0){
        return s;
    }

    std::vector<uint8_t> tx;
    tx.resize(1 + 8 + 8);
    uint16_t offset = 9;

    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::Read: {
            if(this->_mode != 2){
                return s;
            }
            if(plain_rx.size() < 8 + 1 + 2){
                return s;
            }

            tx[0] = m5::stl::to_underlying(ResponseCode::Read);

            const uint8_t block_count = plain_rx[8];
            if(block_count < 1 || 255 < (10 + 2 + 1 + (16 * block_count) + 8 + 5)){
                tx.resize(1 + 8 + 2 + 8 + 6);
                tx[offset++] = 0xff;
                tx[offset++] = 0xa2;
                break;
            }
            if(plain_rx.size() < 8 + 1 + (2 * block_count)){
                return s;
            }
            uint8_t block_offset = 8 + 1;
            uint16_t error = 0x0000;

            tx[offset++] = 0x00;
            tx[offset++] = 0x00;

            tx.resize(1 + 8 + 2 + 1 + (16 * block_count) + 8 + 5);
            tx[offset++] = block_count;

            for (uint8_t i = 0; i < block_count; i++) {
                const block_t b = block_t::from(plain_rx.data() + block_offset);
                block_offset += 2 + b.is_3byte();

                if(b.access_mode() != 0b000){
                    error = ((i + 1) << 8) | 0xA7;
                    break;
                }

                const uint8_t order = b.order();
                if(_auth_state.service_count <= order){
                    error = ((i + 1) << 8) | 0xA3;
                    break;
                }

                const uint16_t service_code = _auth_state.services[order];
                if(!f::FeliCaStandard::is_service_code(service_code)){
                    error = ((i + 1) << 8) | 0xA4;
                    break;
                }

                const uint16_t service_index = find_service(service_code);
                if(service_index == 0xffff){
                    error = ((i + 1) << 8) | 0xA6;
                    break;
                }
                const auto service = this->_services[service_index];

                if(service.block_count <= b.block()){
                    error = ((i + 1) << 8) | 0xA8;
                    break;
                }

                if(service.service_block == nullptr){
                    memset(tx.data() + offset, 0x00, 16);
                }
                else {
                    memcpy(tx.data() + offset, service.service_block + (b.block() * 16), 16);
                }

                offset += 16;
            }

            if(error != 0x0000){
                tx.resize(1 + 8 + 2 + 8 + 6);
                tx[9] = error >> 8;
                tx[10] = error & 0xff;
            }
            break;
        }

        default:
            return s;
    }

    
    this->_auth_state.transaction_count = transaction_count + 1;
    tx[1] = (this->_auth_state.transaction_count) & 0xff;
    tx[2] = (this->_auth_state.transaction_count >> 8) & 0xff;
    memcpy(tx.data() + 3, this->_auth_state.transaction_id + 2, 6);

    f::FeliCaStandard::calculate_mac(tx[0], tx.data() + 1, tx.size() - 1 - 8, tx.data() + tx.size() - 8);

    crypto::des::des_cbc_encrypt(&ctx, tx.data() + 1, tx.data() + 1, tx.size() - 1);

    return _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
}

EmulationLayerF::State EmulationLayerF::receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len)
{
    if (!rx || rx_len < 2) {
        return State::Communicated;
    }

    if(_callback != nullptr){
        static uint8_t tx[256];
        static uint32_t tx_len;
        _callback(rx, rx_len, tx, &tx_len);

        tx_len--;

        return _impl->transmit(tx + 1, tx_len, tx_len * 2) ? State::Selected : s;
    }

    State ret = s;

    if(this->_picc.type == f::Type::FeliCaLiteS) {
        switch (static_cast<CommandCode>(rx[1])) {
            case CommandCode::Polling:
                // M5_LIB_LOGE(" SREQ:%02X%02X %u %u", rx[2], rx[3], rx[4], rx[5]);
                if (rx_len == 6 &&
                    (is_system_code_lite(rx + 2) || is_system_code_ndef(rx + 2) || is_system_code_wildcard(rx + 2))) {
                    uint8_t SENSF_RES[1 + 8 + 8 + 2] = {m5::stl::to_underlying(ResponseCode::Polling)};
                    memcpy(SENSF_RES + 1, _picc.m, 16);

                    // Request code
                    bool req = (rx[4] == 1 || rx[4] == 2);
                    if (rx[4] == 1) {  // request system code
                        SENSF_RES[17] = rx[2];
                        SENSF_RES[18] = rx[3];
                    }
                    if (rx[4] == 2) {  // request communication performance
                        SENSF_RES[17] = 0x00;
                        SENSF_RES[18] = 0x83;  // Auto detect, 424, 212
                    }
                    if (is_system_code_ndef(rx + 2)) {
                        auto ptr = block_to_address(_memory, _memory_size, lite_s::MC.number);
                        if (!ptr || ptr[3] == 0x00) {  // SYS_OP is not support NDEF
                            break;
                        }
                    }
                    // M5_LIB_LOGE(" SRES:%u", sizeof(SENSF_RES) - (2 * !req));

                    // Timeslot
                    if (rx[5]) {
                        const uint8_t slot_count = 1 << rx[5];
                        const uint8_t slot       = (_picc.idm[7] ^ _picc.idm[6]) & (slot_count - 1);
                        m5::utility::delayMicroseconds(2417 + slot * 1208);
                    }

                    // ret = _impl->transmit(SENSF_RES, sizeof(SENSF_RES), 1) ? State::Selected : s;
                    _impl->transmit(SENSF_RES, sizeof(SENSF_RES) - (2 * !req), 1);
                    if (s == State::Communicated) {
                        ret = State::Selected;
                    }
                }
                break;

            case CommandCode::ReadWithoutEncryption:
                // M5_LIB_LOGE("RD:");
                // m5::utility::log::dump(rx, rx_len, false);
                if (rx_len >= 15 && memcmp(_picc.idm, rx + 2, sizeof(_picc.idm)) == 0) {
                    uint16_t sc = rx[11] | (uint16_t)rx[12];

                    std::vector<uint8_t> tx{};
                    tx.resize(1 + 1 + 8 + 2 + 1 + 16 * rx[13]);

                    uint32_t offset{};
                    tx[offset++] = m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption);  // Response code
                    memcpy(tx.data() + 1, _picc.idm, 8);                                         // IDm
                    offset += 8;
                    tx[offset++]          = 0;  // Status 1
                    tx[offset++]          = 0;  // Status 2
                    tx[offset++]          = 0;  // Number of blocks
                    uint32_t block_offset = 14;
                    bool error{};
                    for (uint_fast8_t i = 0; i < rx[13]; ++i) {
                        block_t b = block_t::from(rx + block_offset);
                        block_offset += 2 + b.is_3byte();
                        auto ptr = can_read_lite_s(b) ? block_to_address(_memory, _memory_size, b.block()) : null_data;
                        if (!ptr || !(sc == service_random_read || sc == service_random_read_write)) {
                            tx[9]  = 1U << i;  // Error block bit
                            tx[10] = 0xA8;     // Invalid block
                            tx.resize(1 + 8 + 2 + 1);
                            error = true;
                            break;
                        }
                        memcpy(tx.data() + offset, ptr, 16);
                        offset += 16;
                    }
                    if (!error) {
                        tx[11] = rx[13];
                    }
                    ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
                }
                break;

            case CommandCode::WriteWithoutEncryption:
                // M5_LIB_LOGE("WT:%u", rx_len);
                if (rx_len >= 32 && memcmp(_picc.idm, rx + 2, sizeof(_picc.idm)) == 0 && rx[10] == 1) {
                    uint16_t sc = rx[11] | (uint16_t)rx[12];

                    uint8_t res[1 + 8 + 2] = {m5::stl::to_underlying(ResponseCode::WriteWithoutEncryption)};
                    memcpy(res + 1, _picc.idm, 8);

                    // TODO check permission, REG register, RC

                    uint32_t block_offset = 14;
                    for (uint_fast8_t i = 0; i < rx[13]; ++i) {
                        block_t b = block_t::from(rx + block_offset);
                        block_offset += 2 + b.is_3byte();
                        auto ptr = block_to_address(_memory, _memory_size, b.block());
                        if (!ptr || sc != service_random_read_write || rx[13] > 2 || is_read_only_lite_s(b)) {
                            res[9]  = 1U << i;
                            res[10] = 0xA8;
                            break;
                        }
                        if (b != lite_s::ID) {
                            memcpy(ptr, rx + rx_len - rx[13] * 16 + i * 16, 16);
                        } else {
                            // ID can write lower 8 bytes
                            memcpy(ptr + 8, rx + rx_len - rx[13] * 16 + i * 16 + 8, 8);
                        }
                    }
                    // m5::utility::log::dump(res, sizeof(res), false);
                    ret = _impl->transmit(res, sizeof(res), 8) ? State::Selected : s;
                }
                break;

            default:
                M5_LIB_LOGE(" CMD:%02X %u", rx[1], rx_len);
                break;
        }
    }
    else if(this->_picc.type == f::Type::FeliCaStandard) {

        switch (static_cast<CommandCode>(rx[1])) {
            case CommandCode::Polling:
                if (rx_len == 6 && is_system_code_match(rx + 2, this->_picc.emulation_sc)) {
                    uint8_t SENSF_RES[1 + 8 + 8 + 2] = {m5::stl::to_underlying(ResponseCode::Polling)};
                    memcpy(SENSF_RES + 1, _picc.m, 16);

                    // Request code
                    bool req = (rx[4] == 1 || rx[4] == 2);
                    if (rx[4] == 1) {  // request system code
                        SENSF_RES[17] = (this->_picc.emulation_sc >> 8) & 0xff;
                        SENSF_RES[18] = (this->_picc.emulation_sc & 0xff);
                    }
                    if (rx[4] == 2) {  // request communication performance
                        SENSF_RES[17] = 0x00;
                        SENSF_RES[18] = 0x83;  // Auto detect, 424, 212
                    }
                    // M5_LIB_LOGE(" SRES:%u", sizeof(SENSF_RES) - (2 * !req));

                    // Timeslot
                    if (rx[5]) {
                        const uint8_t slot_count = 1 << rx[5];
                        const uint8_t slot       = (_picc.idm[7] ^ _picc.idm[6]) & (slot_count - 1);
                        m5::utility::delayMicroseconds(2417 + slot * 1208);
                    }

                    // ret = _impl->transmit(SENSF_RES, sizeof(SENSF_RES), 1) ? State::Selected : s;
                    _impl->transmit(SENSF_RES, sizeof(SENSF_RES) - (2 * !req), 1);
                    if (s == State::Communicated) {
                        ret = State::Selected;
                    }
                }
                break;
            
            case CommandCode::RequestService:
            case CommandCode::RequestResponse:
            case CommandCode::ReadWithoutEncryption:
            case CommandCode::WriteWithoutEncryption:
            case CommandCode::SearchServiceCode:
            case CommandCode::RequestSystemCode:
            case CommandCode::Authentication1:
            case CommandCode::Authentication2:
            case CommandCode::RequestServicev2:
            case CommandCode::ResetMode:
                ret = receive_standard_callback_plain(s, rx, rx_len);
                break;
            
            case CommandCode::Read:
            case CommandCode::Write:
                ret = receive_standard_callback_secure(s, rx, rx_len);
                break;

            default:
                M5_LIB_LOGE(" CMD:%02X %u", rx[1], rx_len);
                break;
        }
    }
    // M5_LIB_LOGE(" --> %u", ret);
    return ret;
}

}  // namespace nfc
}  // namespace m5
