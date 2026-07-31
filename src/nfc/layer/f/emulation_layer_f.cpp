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
#include <SD.h>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {

constexpr uint32_t rc_offset       = 16u * (lite_s::REG.number + 1);
constexpr uint32_t wcnt_offset     = rc_offset + 16u * 9;
constexpr uint32_t crc_ceck_offset = wcnt_offset + 16u * 3;
constexpr uint8_t null_data[16]{};

inline bool is_system_code_match(const uint8_t poll_sc[2], const uint16_t sc){
    const bool msb_match = (poll_sc[0] == 0xff) || (poll_sc[0] == ((sc >> 8) & 0xff));
    const bool lsb_match = (poll_sc[1] == 0xff) || (poll_sc[1] == (sc & 0xff));

    return msb_match && lsb_match;
}
}  // namespace

namespace m5 {
namespace nfc {

EmulationLayerF::~EmulationLayerF() = default;

EmulationLayerF::Emulator::Emulator(
            uint8_t* memory,
            const size_t size
        ): _memory(memory), _memory_size(size){

    uint16_t system_index = 0;

    if(get_system_address(_memory, size, 0, system_index) == 0xffff){
        return;
    }

    uint16_t index = system_index;

    while(index < (size >> 4)){
        uint16_t next = index;
        const uint16_t area_address = get_area_address(_memory, size, index, next);

        if(area_address == 0xffff){
            break;
        }

        this->_areas.push_back(Area(_memory + (area_address << 4)));

        index = next;
    }

    index = system_index;

    while(index < (size >> 4)){
        uint16_t next = index;
        const uint16_t service_address = get_service_address(_memory, size, index, next);

        if(service_address == 0xffff){
            break;
        }

        this->_services.push_back(Service(_memory + (service_address << 4)));

        index = next;
    }

    index = system_index;

    while(index < (size >> 4)){
        uint16_t next = index;
        const uint16_t serviceBlock_address = get_serviceblock_address(_memory, size, index, next);

        if(serviceBlock_address == 0xffff){
            break;
        }

        this->_service_blocks.push_back(ServiceBlock(_memory + (serviceBlock_address << 4)));

        index = next;
    }
}
bool EmulationLayerF::Emulator::begin(){
    if(_initialized){
        return false;
    }

    if(_areas.size() == 0){
        return false;
    }
    if(_areas[0].area_code() != 0x0000){
        return false;
    }
    if(_areas[0].end_service_code() != 0xFFFE){
        return false;
    }

    _mode = 0;
    
    std::sort(_areas.begin(), _areas.end());
    std::sort(_services.begin(), _services.end());
    std::sort(_service_blocks.begin(), _service_blocks.end());

    for(uint16_t i = 0; i < _areas.size(); i++){
        if(!FeliCaStandard::is_area_code(_areas[i].area_code())){
            return false;
        }
        if(0 < i && _areas[i - 1].area_code() == _areas[i].area_code()){
            return false;
        }
    }
    for(uint16_t i = 0; i < _services.size(); i++){
        if(!FeliCaStandard::is_service_code(_services[i].service_code())){
            return false;
        }
        if(0 < i && _services[i - 1].service_code() == _services[i].service_code()){
            return false;
        }
        if(find_service_block(_services[i].service_number()) == _service_blocks.end()){
            return false;
        }
    }

    _initialized = true;
    return true;
}

bool EmulationLayerF::begin(const Emulator &emulator,
    void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*),
    const bool auto_res, const bool listen_any){

    const std::vector<Emulator> _emulators{emulator};

    return begin(
        _emulators,
        callback,
        auto_res,
        listen_any
    );
}

bool EmulationLayerF::begin(const std::vector<Emulator> &emulators,
                            void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*),
                            const bool auto_res, const bool listen_any)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
        return false;
    }

    if(emulators.empty()){
        return false;
    }
    
    _emulators = emulators;

    for(uint8_t i = 1; i < emulators.size(); i++){
        for(uint8_t j = 0; j < i; j++){
            if(std::memcmp(_emulators[j].idm(), emulators[i].idm(), 8) == 0){
                return false;
            }
        }
    }

    for(auto &emulator: _emulators){
        if(!emulator.begin()){
            return false;
        }
    }

    _callback    = callback;
    _current_system_index = 0;

    _state = _impl->start_emulation(
        _emulators[_current_system_index].system_code(),
        _emulators[_current_system_index].idm(),
        _pmm,
        auto_res, listen_any) ? State::Off : State::None;
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
            _current_system_index = (_current_system_index + 1) % _emulators.size();
            _impl->set_sens_res(
                _emulators[_current_system_index].system_code(),
                _emulators[_current_system_index].idm(),
                _pmm
            );
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

std::vector<EmulationLayerF::Area>::iterator EmulationLayerF::Emulator::find_area(const uint16_t area_code){
    if(!f::FeliCaStandard::is_area_code(area_code)){
        return _areas.end();
    }

    return std::find(this->_areas.begin(), this->_areas.end(), area_code);
}
std::vector<EmulationLayerF::Service>::iterator EmulationLayerF::Emulator::find_service(const uint16_t service_code){
    if(!f::FeliCaStandard::is_service_code(service_code)){
        return _services.end();
    }

    return std::find(this->_services.begin(), this->_services.end(), service_code);
}
std::vector<EmulationLayerF::ServiceBlock>::iterator EmulationLayerF::Emulator::find_service_block(const uint16_t service_number){
    if(0x03FF < service_number){
        return _service_blocks.end();
    }

    return std::find(this->_service_blocks.begin(), this->_service_blocks.end(), service_number);
}

bool EmulationLayerF::Emulator::receive_standard_callback_plain(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx){
    if(rx_len < 10){
        return false;
    }

    // Check if the destination IDm matches this device's IDm
    if(memcmp(idm(), rx + 2, 8) != 0){
        return false;
    }
    // ========================================================
    // After this point, it is guaranteed that the packet is 
    // addressed to this device. Therefore, it must ALWAYS 
    // return true, even if data parsing fails.
    //
    // If you do not want to send a response (e.g., due to an 
    // 'rx' parsing error), resize the 'tx' buffer to 0 
    // (tx.resize(0) or tx.clear()) before returning true.
    // ========================================================

    tx.resize(0);

    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::Authentication1: {
            if(rx_len < 10 + 1 + 2 + 1 + 2 + 8){
                return true;
            }
            uint16_t offset = 10;
            const uint8_t area_code_count = rx[offset++];
            if(area_code_count == 0 || 16 < area_code_count){
                return true;
            }
            if(rx_len < offset + (2 * area_code_count) + 1 + 2 + 8){
                return true;
            }
            const uint8_t* area_code_list = rx + offset;
            offset += (2 * area_code_count);

            const uint8_t service_code_count = rx[offset++];
            if(service_code_count == 0 || 16 < service_code_count){
                return true;
            }
            if(rx_len != offset + (2 * service_code_count) + 8){
                return true;
            }
            const uint8_t* service_code_list = rx + offset;
            offset += (2 * service_code_count);

            const uint8_t* area_keys[16];
            for(uint8_t i = 0; i < area_code_count; i++){
                const uint16_t area_code = ((uint16_t)*(area_code_list + (i * 2))) | (((uint16_t)*(area_code_list + (i * 2) + 1)) << 8);

                if(area_code == 0xffff){
                    area_keys[i] = des_key().key();
                }
                else if(FeliCaStandard::is_area_code(area_code)){
                    const auto it = find_area(area_code);
                    if(it == _areas.end()){
                        return true;
                    }
                    area_keys[i] = (*it).des_key().key();
                }
                else if(FeliCaStandard::is_service_code(area_code)){
                    if(FeliCaStandard::is_auth_required(area_code)){
                        const auto it = find_service(area_code);
                        if(it == _services.end()){
                            return true;
                        }
                        area_keys[i] = (*it).des_key().key();
                    }
                    else{
                        area_keys[i] = nullptr;
                    }
                }
                else{
                    return true;
                }
            }

            const uint8_t* service_keys[16];
            for(uint8_t i = 0; i < service_code_count; i++){
                const uint16_t service_code = ((uint16_t)*(service_code_list + (i * 2))) | (((uint16_t)*(service_code_list + (i * 2) + 1)) << 8);

                if(service_code == 0xffff){
                    service_keys[i] = des_key().key();
                }
                else if(FeliCaStandard::is_area_code(service_code)){
                    const auto it = find_area(service_code);
                    if(it == _areas.end()){
                        return true;
                    }
                    service_keys[i] = (*it).des_key().key();
                }
                else if(FeliCaStandard::is_service_code(service_code)){
                    if(FeliCaStandard::is_auth_required(service_code)){
                        const auto it = find_service(service_code);
                        if(it == _services.end()){
                            return true;
                        }
                        service_keys[i] = (*it).des_key().key();
                    }
                    else{
                        service_keys[i] = nullptr;
                    }
                }
                else{
                    return true;
                }
            }

            this->_mode = 1;
            
            for(uint8_t i = 0; i < service_code_count; i++){
                this->_auth_state.services[i] = ((uint16_t)*(service_code_list + (i * 2))) | (((uint16_t)*(service_code_list + (i * 2) + 1)) << 8);
            }
            this->_auth_state.service_count = service_code_count;

            uint8_t gsk[8];
            uint8_t usk[8];
            FeliCaStandard::generate_groupkey(des_key().key(), area_code_count, area_keys, service_code_count, service_keys, gsk, usk);

            for(uint8_t i = 0; i < 8; i++){
                gsk[i] ^= idm()[i];
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
            crypto::des::des_set_key(&ctx_beta, gsk);

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
            tx.resize(1 + 8 + 8 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::Authentication1);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;

            crypto::des::store64_be(transaction_id, tx.data() + offset);
            offset += 8;
            crypto::des::store64_be(challenge_2, tx.data() + offset);
            offset += 8;

            return true;
        }
        case CommandCode::Authentication2: {
            if(this->_mode != 1){
                return true;
            }

            if(rx_len < 10 + 8){
                return true;
            }

            uint64_t transaction_key = crypto::des::load64_be(rx + 10);

            crypto::des::des_ctx_t ctx_l;
            crypto::des::des_set_key_uint64(&ctx_l, this->_auth_state.key_l);

            crypto::des::des_ctx_t ctx;
            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.key_alpha);

            transaction_key = crypto::des::tdes_decrypt_uint64(&ctx, &ctx_l, &ctx, transaction_key);
            if(transaction_key != this->_auth_state.transaction_key){
                return true;
            }

            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);

            uint16_t offset = 0;
            tx.resize(1 + 8 + 8 + 8 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::Authentication2);
            
            this->_auth_state.transaction_count = 0;

            tx[offset++] = this->_auth_state.transaction_count & 0xff;
            tx[offset++] = (this->_auth_state.transaction_count >> 8) & 0xff;
            memcpy(tx.data() + offset, this->_auth_state.transaction_id + 2, 6);
            offset += 6;

            memcpy(tx.data() + offset, idi(), 8);
            offset += 8;

            memcpy(tx.data() + offset, pmi(), 8);
            offset += 8;

            FeliCaStandard::calculate_mac(tx[0], tx.data() + 1, 8 + 8 + 8, tx.data() + offset);
            offset += 8;

            crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);
            crypto::des::des_cbc_encrypt(&ctx, tx.data() + 1, tx.data() + 1, 8 + 8 + 8 + 8);

            this->_mode = 2;

            return true;
        }

        case CommandCode::RequestService: {
            if(rx_len < 10 + 1 + 2){
                return true;
            }

            const uint8_t node_count = rx[10];
            if((node_count < 1 || 32 < node_count) || rx_len != 10 + 1 + 2 * node_count){
                return true;
            }

            const uint8_t* node_code_list = rx + 11;

            uint16_t offset = 0;
            tx.resize(1 + 8 + 1 + 2 * node_count);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::RequestService);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;

            tx[offset++] = node_count;
            for(uint8_t i = 0; i < node_count; i++){
                const uint16_t node_code = ((uint16_t)*(node_code_list + (i * 2))) | (((uint16_t)*(node_code_list + (i * 2) + 1)) << 8);
                uint16_t key_version = 0xffff;

                if(node_code == 0xffff){
                    key_version = des_key().version();
                }
                else if(FeliCaStandard::is_area_code(node_code)){
                    const auto it = find_area(node_code);
                    if(it < _areas.end()){
                        key_version = (*it).des_key().version();
                    }
                }
                else if(FeliCaStandard::is_service_code(node_code)){
                    const auto it = find_service(node_code);
                    if(it < _services.end()){
                        key_version = (*it).des_key().version();
                    }
                }

                tx[offset + i * 2] = key_version & 0xff;
                tx[offset + i * 2 + 1] = (key_version >> 8) & 0xff;
            }

            return true;
        }
        case CommandCode::RequestResponse: {
            if(rx_len != 10){
                return true;
            }

            uint16_t offset = 0;
            tx.resize(1 + 8 + 1);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::RequestResponse);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;
            tx[offset++] = this->_mode;

            return true;
        }
        case CommandCode::SearchServiceCode: {
            if(rx_len != 10 + 2){
                return true;
            }

            const uint16_t node_index = (((uint16_t)rx[11]) << 8) | rx[10];

            uint16_t node_code;
            uint16_t end_service_code = 0xffff;
            if(node_index < this->_areas.size()){
                node_code = this->_areas[node_index].area_code();
                end_service_code = this->_areas[node_index].end_service_code();
            }
            else if(node_index < this->_areas.size() + this->_services.size()){
                node_code = this->_services[node_index - this->_areas.size()].service_code();
            }
            else{
                node_code = 0xffff;
            }

            uint16_t offset = 0;

            if(f::FeliCaStandard::is_area_code(node_code)){
                tx.resize(1 + 8 + 4);
            }
            else{
                tx.resize(1 + 8 + 2);
            }

            tx[offset++] = m5::stl::to_underlying(ResponseCode::SearchServiceCode);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;

            tx[offset++] = node_code & 0xff;
            tx[offset++] = (node_code >> 8) & 0xff;

            if(f::FeliCaStandard::is_area_code(node_code)){
                tx[offset++] = end_service_code & 0xff;
                tx[offset++] = (end_service_code >> 8) & 0xff;
            }

            return true;
        }
        case CommandCode::ResetMode: {
            if(rx_len != 12){
                return true;
            }

            this->_mode = 0x00;

            uint16_t offset = 0;
            tx.resize(1 + 8 + 2);

            tx[offset++] = m5::stl::to_underlying(ResponseCode::ResetMode);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;
            tx[offset++] = 0x00;
            tx[offset++] = 0x00;

            return true;
        }
        case CommandCode::ReadWithoutEncryption: {
            if(this->_mode != 0){
                return true;
            }
            if(rx_len < 10 + 1 + 2 + 1 + 2){
                return true;
            }

            uint16_t offset = 0;
            tx.resize(1 + 8);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption);
            memcpy(tx.data() + offset, idm(), 8);
            offset += 8;

            const uint8_t service_count = rx[10];
            if(service_count < 1 || 16 < service_count){
                tx.resize(1 + 8 + 2);
                tx[offset++] = 0xff;
                tx[offset++] = 0xa1;
                return true;
            }
            if(rx_len < 10 + 1 + (2 * service_count) + 1 + 2){
                tx.resize(0);
                return true;
            }
            const uint8_t* service_list = rx + 10 + 1;

            const uint8_t block_count = rx[10 + 1 + (2 * service_count)];
            if(block_count < 1 || 255 < (10 + 2 + 1 + (16 * block_count))){
                tx.resize(1 + 8 + 2);
                tx[offset++] = 0xff;
                tx[offset++] = 0xa2;

                return true;
            }
            if(rx_len < 10 + 1 + (2 * service_count) + 1 + (2 * block_count)){
                tx.resize(0);
                return true;
            }

            uint8_t block_offset = 10 + 1 + (2 * service_count) + 1;
            uint16_t error = 0x0000;

            tx.resize(1 + 8 + 2 + 1 + (16 * block_count));

            tx[offset++] = 0x00;
            tx[offset++] = 0x00;
            tx[offset++] = block_count;

            for (uint8_t i = 0; i < block_count; i++) {
                if(rx_len <= block_offset){
                    tx.resize(0);
                    return true;
                }

                const uint8_t remaining_size = rx_len - block_offset;
                if(remaining_size < (((rx[block_offset] & 0x80) == 0)? 1 : 0) + 2){
                    tx.resize(0);
                    return true;
                }
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

                const auto service = find_service(service_code);
                if(service == _services.end()){
                    error = ((i + 1) << 8) | 0xA6;
                    break;
                }
                const auto service_block = find_service_block((*service).service_number());

                if(!(*service_block).read(b.block(), tx.data() + offset,
                    ((*service).service_code() & 0b001100) == 0b001100)){
                    error = ((i + 1) << 8) | 0xA8;
                    break;
                }

                offset += 16;
            }

            if(error != 0x0000){
                tx.resize(1 + 8 + 2);
                tx[9] = error >> 8;
                tx[10] = error & 0xff;
            }

            return true;

        }
        case CommandCode::WriteWithoutEncryption:
            break;
    }

    return true;
}

bool EmulationLayerF::Emulator::receive_standard_callback_secure(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx){
    if(rx_len < 18 || (rx_len - 2) % 8 != 0){
        return false;
    }
    if(!(this->_mode == 2 || this->_mode == 3)){
        return false;
    }
    if(this->_auth_state.transaction_count == 0xffff){
        return false;
    }
    std::vector<uint8_t> plain_rx(rx_len - 2);

    crypto::des::des_ctx_t ctx;
    crypto::des::des_set_key_uint64(&ctx, this->_auth_state.transaction_key);
    crypto::des::des_cbc_decrypt(&ctx, rx + 2, plain_rx.data(), plain_rx.size());

    // Check if the destination ID matches this device's ID
    if(std::memcmp(plain_rx.data() + 2, this->_auth_state.transaction_id + 2, 6) != 0){

        return false;
    }
    // ========================================================
    // After this point, it is guaranteed that the packet is 
    // addressed to this device. Therefore, it must ALWAYS 
    // return true, even if data parsing fails.
    //
    // If you do not want to send a response (e.g., due to an 
    // 'rx' parsing error), resize the 'tx' buffer to 0 
    // (tx.resize(0) or tx.clear()) before returning true.
    // ========================================================

    tx.resize(0);

    const uint16_t transaction_count = plain_rx[0] | (((uint16_t)plain_rx[1]) << 8);
    if(transaction_count <= this->_auth_state.transaction_count){
        return true;
    }

    std::vector<uint8_t> calculated_mac(8);
    f::FeliCaStandard::calculate_mac(rx[1], plain_rx.data(), plain_rx.size() - 8, calculated_mac.data());
    if(std::memcmp(plain_rx.data() + plain_rx.size() - 8, calculated_mac.data(), 8) != 0){
        return true;
    }

    plain_rx.resize(plain_rx.size() - 8);

    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::Read: {
            if(this->_mode != 2){
                return true;
            }
            if(plain_rx.size() < 8 + 1 + 2){
                return true;
            }

            uint16_t offset = 0;
            tx.resize(1 + 8 + 2);
            tx[offset++] = m5::stl::to_underlying(ResponseCode::Read);
            offset += 8;

            const uint8_t block_count = plain_rx[8];

            if(block_count < 1 || 255 < (10 + 2 + 1 + (16 * block_count) + 8 + 5)){
                tx[offset++] = 0xff;
                tx[offset++] = 0xa2;
                break;
            }
            if(plain_rx.size() < 8 + 1 + (2 * block_count)){
                tx.resize(0);
                return true;
            }
            uint8_t block_offset = 8 + 1;
            uint16_t error = 0x0000;

            tx[offset++] = 0x00;
            tx[offset++] = 0x00;

            tx.resize(1 + 8 + 2 + 1 + (16 * block_count));
            tx[offset++] = block_count;

            for (uint8_t i = 0; i < block_count; i++) {
                if(plain_rx.size() <= block_offset){
                    tx.resize(0);
                    return true;
                }

                const uint8_t remaining_size = plain_rx.size() - block_offset;
                if(remaining_size < (((plain_rx[block_offset] & 0x80) == 0)? 1 : 0) + 2){
                    tx.resize(0);
                    return true;
                }
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

                const auto service = find_service(service_code);
                if(service == _services.end()){
                    error = ((i + 1) << 8) | 0xA6;
                    break;
                }
                const auto service_block = find_service_block((*service).service_number());

                if(!(*service_block).read(b.block(), tx.data() + offset,
                    ((*service).service_code() & 0b001100) == 0b001100)){
                    error = ((i + 1) << 8) | 0xA8;
                    break;
                }

                offset += 16;
            }

            if(error != 0x0000){
                tx.resize(1 + 8 + 2);
                tx[9] = error >> 8;
                tx[10] = error & 0xff;
            }

            break;
        }

        default:
            tx.resize(0);
            return true;
    }

    if((tx.size() - 1) % 8 != 0){
        tx.resize(tx.size() + 8 - ((tx.size() - 1) % 8) + 8, 0x00);
    }
    else{
        tx.resize(tx.size() + 8, 0x00);
    }
    
    this->_auth_state.transaction_count = transaction_count + 1;
    tx[1] = (this->_auth_state.transaction_count) & 0xff;
    tx[2] = (this->_auth_state.transaction_count >> 8) & 0xff;
    memcpy(tx.data() + 3, this->_auth_state.transaction_id + 2, 6);

    f::FeliCaStandard::calculate_mac(tx[0], tx.data() + 1, tx.size() - 1 - 8, tx.data() + tx.size() - 8);

    crypto::des::des_cbc_encrypt(&ctx, tx.data() + 1, tx.data() + 1, tx.size() - 1);

    return true;
}

bool EmulationLayerF::Emulator::receive_emulator_callback(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx){
    if(rx_len < 10){
        return false;
    }
    tx.resize(0);

    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::RequestService:
        case CommandCode::RequestResponse:
        case CommandCode::ReadWithoutEncryption:
        case CommandCode::WriteWithoutEncryption:
        case CommandCode::SearchServiceCode:
        case CommandCode::Authentication1:
        case CommandCode::Authentication2:
        case CommandCode::RequestServicev2:
        case CommandCode::ResetMode:
            return receive_standard_callback_plain(rx, rx_len, tx);
        
        case CommandCode::Read:
        case CommandCode::Write:
            return receive_standard_callback_secure(rx, rx_len, tx);

        default:
            M5_LIB_LOGE(" CMD:%02X %u", rx[1], rx_len);
            return false;
    }
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

    CommandCode cmd = static_cast<CommandCode>(rx[1]);

    if(cmd == CommandCode::Polling){
        if(rx_len != 6){
            return s;
        }

        const auto target_system = std::find_if(_emulators.begin(), _emulators.end(),
            [rx](const Emulator &emulator) {
                return is_system_code_match(rx + 2, emulator.system_code());
            }
        );
        if(target_system == _emulators.end()){
            return s;
        }

        uint8_t SENSF_RES[1 + 8 + 8 + 2] = {m5::stl::to_underlying(ResponseCode::Polling)};

        memcpy(SENSF_RES + 1, (*target_system).idm(), 8);
        memcpy(SENSF_RES + 9, _pmm, 8);

        // Request code
        bool req = (rx[4] == 1 || rx[4] == 2);
        if (rx[4] == 1) {  // request system code
            SENSF_RES[17] = ((*target_system).system_code() >> 8) & 0xff;
            SENSF_RES[18] = ((*target_system).system_code() & 0xff);
        }
        if (rx[4] == 2) {  // request communication performance
            SENSF_RES[17] = 0x00;
            SENSF_RES[18] = 0x83;  // Auto detect, 424, 212
        }
        // M5_LIB_LOGE(" SRES:%u", sizeof(SENSF_RES) - (2 * !req));

        // Timeslot
        if (rx[5]) {
            const uint8_t slot_count = 1 << rx[5];
            const uint8_t slot       = ((*target_system).idm()[7] ^ (*target_system).idm()[6]) & (slot_count - 1);
            m5::utility::delayMicroseconds(2417 + slot * 1208);
        }

        // ret = _impl->transmit(SENSF_RES, sizeof(SENSF_RES), 1) ? State::Selected : s;
        _impl->transmit(SENSF_RES, sizeof(SENSF_RES) - (2 * !req), 1);
        if (s == State::Communicated) {
            ret = State::Selected;
        }
    }
    else if(cmd == CommandCode::RequestSystemCode){
        if(rx_len != 10){
            return s;
        }

        const auto target_system = std::find_if(_emulators.begin(), _emulators.end(),
            [rx](const Emulator &emulator) {
                return std::memcmp(rx + 2, emulator.idm(), 8) == 0;
            }
        );
        if(target_system == _emulators.end()){
            return s;
        }

        std::vector<uint8_t> tx(1 + 8 + 1 + (2 * _emulators.size()));
        tx[0] = m5::stl::to_underlying(ResponseCode::RequestSystemCode);
        memcpy(tx.data() + 1, (*target_system).idm(), 8);
        tx[9] = _emulators.size();

        for(uint8_t i = 0; i < _emulators.size(); i++){
            const uint16_t sc = _emulators[i].system_code();
            tx[10 + (i * 2)] = (sc >> 8) & 0xff;
            tx[10 + (i * 2) + 1] = sc & 0xff;
        }

        ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;;
    }
    else{
        std::vector<uint8_t> tx(255);

        do {
            const bool result = _emulators[_current_system_index].receive_emulator_callback(rx, rx_len, tx);

            if(result){
                if(0 < tx.size()){
                    ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
                }

                return ret;
            }
        } while(false);

        for(uint8_t i = 0; i < _emulators.size(); i++){
            auto& system = _emulators[i];
            if(std::memcmp(system.idm(), _emulators[_current_system_index].idm(), 8) == 0){
                continue;
            }

            const bool result = system.receive_emulator_callback(rx, rx_len, tx);

            if(!result){
                continue;
            }

            _current_system_index = i;
            if(0 < tx.size()){
                return _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Selected : s;
            }
        }
    }

    // M5_LIB_LOGE(" --> %u", ret);
    return ret;
}

bool EmulationLayerF::SDStorage::open(const bool writeable){
    if(!_initialized){
        return false;
    }
    if(_is_open){
        return true;
    }

    if(_sd == nullptr){
        return false;
    }

    if(writeable){
        _fp = (*_sd).open(_filename.c_str(), FILE_WRITE);
    }
    else{
        _fp = (*_sd).open(_filename.c_str(), FILE_READ);
    }

    if(_fp){
        _is_open = true;
        return true;
    }
    else{
        return false;
    }
}

bool EmulationLayerF::SDStorage::close(){
    if(!_initialized){
        return false;
    }
    if(!_is_open){
        return true;
    }

    _fp.flush();
    _fp.close();
    _is_open = false;

    return true;
}

bool EmulationLayerF::SDStorage::begin(fs::SDFS& sd, const std::string& filename){
    if(_initialized){
        return true;
    }
    _initialized = true;

    this->_sd = &sd;
    this->_filename = filename;

    open();
    const uint16_t memory_size = _fp.available() & 0xfff0;
    _block_memory.resize(memory_size);
    const size_t readed = _fp.read(_block_memory.data(), memory_size);

    if(memory_size != readed){
        close();
        _initialized = false;
        return false;
    }

    _changed = false;

    return close();
}

bool EmulationLayerF::SDStorage::read(const uint16_t block_address, const uint16_t block_num, uint8_t* buf, const bool cyclic) const{
    if(!_initialized){
        return false;
    }

    if((_block_memory.size() >> 4) <= (block_address + 1 + block_num)){
        return false;
    }

    const size_t address = (block_address + 1) * 16;

    if(cyclic){
        const uint16_t block_count = (((uint16_t)_block_memory[address] & 0x3F) << 8) | _block_memory[address + 1];
        const uint16_t cyclic_index = (((uint16_t)_block_memory[address + 4]) << 8) | _block_memory[address + 5];

        const size_t read_address = ((cyclic_index + block_num) % (block_count - 1)) * 16;

        memcpy(buf, _block_memory.data() + read_address, 16);
    }
    else{
        memcpy(buf, _block_memory.data() + address + (block_num * 16), 16);
    }

    return true;
}

void EmulationLayerF::SDStorage::update(){
    if(!_initialized){
        return;
    }
    if(!_is_open){
        return;
    }
    if(!_changed){
        return;
    }

    _fp.write(_block_memory.data(), _block_memory.size());
    _fp.flush();
}

}  // namespace nfc
}  // namespace m5
