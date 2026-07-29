/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_f.hpp
  @brief Emulation layer for NFC-F

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: internal state-machine names (borrowed from NFC-A's ISO14443-3 terminology for consistency)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP
#define M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP

#include "nfc/f/nfcf.hpp"
#include "nfc/crypto/des.hpp"
#include <vector>
#include <memory>
#include <string.h>

namespace m5 {

namespace unit {
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit

namespace nfc {

/*!
  @class EmulationLayerF
  @brief Common interface layer for each chip of the NFC-F emulation
 */
class EmulationLayerF {
public:
    /*!
      @enum State
      @brief Emulation state for NFC-F
     */
    enum class State { None, Off, Communicated, Selected };

    struct Adapter;
    struct Service;
    struct Area;
    struct DesKey {
        uint8_t key[8];
        uint16_t version = 0;

        DesKey(): version(0){
            memset(key, 0, 8);
        }
        DesKey(const uint8_t key[8], const uint16_t version): version(version){
            memcpy(this->key, key, 8);
        }
        DesKey(const uint64_t key, const uint16_t version): version(version){
            crypto::des::store64_be(key, this->key);
        }
    };
    
    //! @brief Construct with UnitST25R3916 (I2C)
    explicit EmulationLayerF(m5::unit::UnitST25R3916& u);
    //! @brief Construct with CapST25R3916 (SPI)
    explicit EmulationLayerF(m5::unit::CapST25R3916& u);
    virtual ~EmulationLayerF();

    //! @brief Gets the current emulation state
    inline State state() const
    {
        return _state;
    }
    //! @brief Gets the emulated PICC information
    inline const m5::nfc::f::PICC& emulatePICC() const
    {
        return _picc;
    }
    //! @brief Gets the expiration time (ms)
    inline uint32_t expiredTime() const
    {
        return _expired_ms;
    }
    //! @brief Sets the expiration time (ms)
    void setExpiredTime(const uint32_t ms)
    {
        _expired_ms = ms;
    }

    //! @brief Begin NFC-F emulation
    bool begin(const m5::nfc::f::PICC& picc, uint8_t* ptr, const uint32_t size,
                const uint8_t idi[8],
                const uint8_t pmi[8],
                const DesKey &system_key,
                const std::vector<Area> &areas,
                const std::vector<Service> &services,
                void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*) = nullptr,
                const bool auto_res = true, const bool listen_any = false);
    //! @brief End NFC-F emulation
    bool end();
    //! @brief Update emulation state machine
    void update();

    virtual State receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len);
    virtual State receive_standard_callback_plain(const State s, const uint8_t* rx, const uint32_t rx_len);
    virtual State receive_standard_callback_secure(const State s, const uint8_t* rx, const uint32_t rx_len);

    virtual uint16_t find_area(const uint16_t area_code);
    virtual uint16_t find_service(const uint16_t service_code);

    union {
        uint8_t m[16]{};
        struct {
            uint8_t idi[f::FELICA_ID_LENGTH];
            uint8_t pmi[f::FELICA_ID_LENGTH];
        };
    };

protected:
    void update_expired();

private:
    void update_off();
    void update_communicated();
    void update_selected();

protected:
    uint8_t* _memory{};
    uint32_t _memory_size{};
    std::vector<Area> _areas{};
    std::vector<Service> _services{};
    DesKey _system_key;

private:
    State _state{}, _prev{};
    uint32_t _expired_ms{60 * 1000u};
    unsigned int _expired_at{};
    std::unique_ptr<Adapter> _impl;
    m5::nfc::f::PICC _picc{};
    uint8_t _mode{0};
    struct {
        uint16_t transaction_count{0};
        uint8_t transaction_id[8];
        uint64_t transaction_key;
        uint8_t service_count{0};
        uint16_t services[16];

        uint64_t key_l;
        uint64_t key_alpha;
    } _auth_state;

    void (*_callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*);
};

///@cond
// Impl for units
struct EmulationLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool start_emulation(const m5::nfc::f::PICC& picc, const bool auto_res = true, const bool listen_any = false) = 0;
    virtual bool stop_emulation()                                                              = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;

    virtual EmulationLayerF::State update_off()          = 0;
    virtual EmulationLayerF::State update_communicated() = 0;
    virtual EmulationLayerF::State update_selected()     = 0;
};
///@endcond

struct EmulationLayerF::Service {
    uint16_t service_code = 0x0008;
    uint16_t block_count = 0;
    DesKey key;
    uint8_t* service_block = nullptr;

    Service(const uint16_t service_code, const DesKey &key, const uint16_t block_count, uint8_t *block):
        service_code(service_code),
        key(key),
        block_count(block_count) {
            this->service_block = block;
        }

    bool operator<(const Service &r) const{
        return this->service_code < r.service_code;
    }
    bool operator<(const uint16_t r) const{
        return this->service_code < r;
    }
    bool operator==(const uint16_t r) const{
        return this->service_code == r;
    }
    friend bool operator<(const Service &l, const Service &r){
        return l.service_code < r.service_code;
    }
    friend bool operator<(const uint16_t &l, const Service &r){
        return l < r.service_code;
    }
};

struct EmulationLayerF::Area {
    uint16_t area_code = 0x0000;
    uint16_t block_count = 0;
    DesKey key;
    uint16_t end_service_code = 0xFFFE;

    Area(const uint16_t area_code, const uint16_t end_service_code, const DesKey &key):
        area_code(area_code),
        end_service_code(end_service_code),
        key(key){}

    bool operator<(const Area &r) const{
        return this->area_code < r.area_code;
    }
    bool operator<(const uint16_t r) const{
        return this->area_code < r;
    }
    bool operator==(const uint16_t r) const{
        return this->area_code == r;
    }
    friend bool operator<(const Area &l, const Area &r){
        return l.area_code < r.area_code;
    }
    friend bool operator<(const uint16_t l, const Area &r){
        return l < r.area_code;
    }
};

}  // namespace nfc
}  // namespace m5
#endif
