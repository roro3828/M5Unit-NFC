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
#include <SD.h>

namespace { 
    inline uint16_t readBE16(const uint8_t* data, size_t index) {
        if(data == nullptr){
            return 0xffff;
        }
        return (data[index] << 8) | data[index + 1];
    }
}

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

    inline static uint16_t get_system_address(const uint8_t* memory,
                        const size_t size,
                        const uint16_t offset,
                        uint16_t& next
                    ){
        for(uint16_t i = offset; i < (size >> 4); i++){
            if((memory[i << 4] & 0xC0) != 0x00){
                continue;
            }
            const uint16_t block_count = readBE16(memory + (i << 4), 0) & 0x3FFF;
            if((size >> 4) < i + block_count){
                continue;
            }
            if(block_count < 4){
                continue;
            }

            next = i + block_count;
            return i;
        }

        next = 0xffff;
        return 0xffff;
    }
    inline static uint16_t get_area_address(const uint8_t* memory,
                        const size_t size,
                        const uint16_t offset,
                        uint16_t& next
                    ){
        for(uint16_t i = offset; i < (size >> 4); i++){
            if((memory[i << 4] & 0xC0) != 0x40){
                continue;
            }
            const uint16_t block_count = readBE16(memory + (i << 4), 0) & 0x3FFF;
            if((size >> 4) < i + block_count){
                continue;
            }
            if(block_count != 1){
                continue;
            }

            next = i + block_count;
            return i;
        }

        next = 0xffff;
        return 0xffff;
    }
    inline static uint16_t get_service_address(const uint8_t* memory,
                        const size_t size,
                        const uint16_t offset,
                        uint16_t& next
                    ){
        for(uint16_t i = offset; i < (size >> 4); i++){
            if((memory[i << 4] & 0xC0) != 0x80){
                continue;
            }
            const uint16_t block_count = readBE16(memory + (i << 4), 0) & 0x3FFF;
            if((size >> 4) < i + block_count){
                continue;
            }
            if(block_count != 1){
                continue;
            }

            next = i + block_count;
            return i;
        }

        next = 0xffff;
        return 0xffff;
    }
    inline static uint16_t get_serviceblock_address(const uint8_t* memory,
                        const size_t size,
                        const uint16_t offset,
                        uint16_t& next
                    ){
        for(uint16_t i = offset; i < (size >> 4); i++){
            if((memory[i << 4] & 0xC0) != 0xC0){
                continue;
            }
            const uint16_t block_count = readBE16(memory + (i << 4), 0) & 0x3FFF;
            if((size >> 4) < i + block_count){
                continue;
            }
            if(1 <= block_count){
                continue;
            }

            next = i + block_count;
            return i;
        }

        next = 0xffff;
        return 0xffff;
    }
    /*!
    @enum State
    @brief Emulation state for NFC-F
    */
    enum class State { None, Off, Communicated, Selected };
    struct SDStorage;

    struct Adapter;
    struct Service;
    struct ServiceBlock;
    struct Area;
    struct DesKey {
        uint16_t version() const{
            return readBE16(_memory, 0);
        }
        const uint8_t* key() const{
            return (_memory + 2);
        }

        DesKey(uint8_t* memory): _memory(memory){}

        private:
        uint8_t* _memory;
    };

    class Emulator {
        public:

        Emulator(
            uint8_t* memory,
            const size_t size
        );

        bool begin();

        bool receive_emulator_callback(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx);

        std::vector<Area>::iterator find_area(const uint16_t area_code);
        std::vector<Service>::iterator find_service(const uint16_t service_code);
        std::vector<ServiceBlock>::iterator find_service_block(const uint16_t service_number);

        uint16_t system_code() const{
            return readBE16(_memory, 2);
        }
        const uint8_t* idm() const{
            return _memory + 8;
        }
        const uint8_t* idi() const{
            return _memory + 16;
        }
        const uint8_t* pmi() const{
            return _memory + 16 + 8;
        }
        DesKey des_key() const{
            return DesKey(_memory + 32 + 6);
        }
        
        protected:
        std::vector<Area> _areas{};
        std::vector<Service> _services{};
        std::vector<ServiceBlock> _service_blocks{};
        uint8_t* _memory;
        size_t _memory_size;

        private:
        /**
         * @brief Standard plain data reception callback.
         * 
         * @param rx     Pointer to the received data buffer.
         * @param rx_len Byte length of the received data.
         * @param tx     Buffer to store the transmission/response data.
         * 
         * @retval true  If the received data is addressed to this device (even if data parsing fails).
         * @retval false If the received data is not addressed to this device, or if the destination is unknown.
         */
        bool receive_standard_callback_plain(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx);
        /**
         * @brief Standard encrypted data reception callback.
         * 
         * @param rx     Pointer to the received data buffer. This data starts from length.
         * @param rx_len Byte length of the received data.
         * @param tx     Buffer to store the encrypted transmission/response data. This data starts from command code.
         * 
         * @retval true  If the received data is addressed to this device (even if data parsing fails).
         * @retval false If the received data is not addressed to this device, or if the destination is unknown.
         */
        bool receive_standard_callback_secure(const uint8_t* rx, const uint32_t rx_len, std::vector<uint8_t> &tx);
        uint32_t _expired_ms{60 * 1000u};
        unsigned int _expired_at{};
        uint8_t _mode;

        bool _initialized{false};

        struct {
            uint16_t transaction_count{0};
            uint8_t transaction_id[8];
            uint64_t transaction_key;
            uint8_t service_count{0};
            uint16_t services[16];

            uint64_t key_l;
            uint64_t key_alpha;
        } _auth_state;
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
    //! @brief Emulators
    inline const std::vector<m5::nfc::EmulationLayerF::Emulator>& emulators()
    {
        return _emulators;
    }

    //! @brief Begin NFC-F emulation
    bool begin(const Emulator &emulator,
                void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*) = nullptr,
                const bool auto_res = true, const bool listen_any = false);

    //! @brief Begin NFC-F emulation
    bool begin(const std::vector<Emulator> &emulators,
                void (*callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*) = nullptr,
                const bool auto_res = true, const bool listen_any = false);
    //! @brief End NFC-F emulation
    bool end();
    //! @brief Update emulation state machine
    void update();

    virtual State receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len);

protected:
    void update_expired();
    std::vector<Emulator> _emulators;
    State _state{}, _prev{};

private:
    void update_off();
    void update_communicated();
    void update_selected();

    uint8_t _pmm[8];

    uint32_t _expired_ms{60 * 1000u};
    unsigned int _expired_at{};
    std::unique_ptr<Adapter> _impl;

    uint8_t _current_system_index = -1;

    void (*_callback)(const uint8_t*, const uint32_t, uint8_t*, uint32_t*);
};

///@cond
// Impl for units
struct EmulationLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool start_emulation(const m5::nfc::f::PICC& picc, const bool auto_res = true, const bool listen_any = false) = 0;
    virtual bool start_emulation(const uint16_t sc, const uint8_t idm[8], const uint8_t pmm[8], const bool auto_res = true, const bool listen_any = false) = 0;
    virtual bool stop_emulation()                                                              = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;

    virtual EmulationLayerF::State update_off()          = 0;
    virtual EmulationLayerF::State update_communicated() = 0;
    virtual EmulationLayerF::State update_selected()     = 0;

    virtual bool set_sens_res(const m5::nfc::f::PICC& picc) = 0;
    virtual bool set_sens_res(const uint16_t sc, const uint8_t idm[8], const uint8_t pmm[8]) = 0;
};
///@endcond

struct EmulationLayerF::SDStorage {
    SDStorage(){
        _is_open = false;
    }

    bool begin(fs::SDFS& sd, const std::string& filename);
    bool open(const bool writeable = false);
    bool close();
    void update();

    bool read(const uint16_t block_address, const uint16_t block_num, uint8_t* buf, const bool cyclic = false) const;
    bool write(const uint16_t block_address, const uint16_t block_num, const uint8_t* buf, const bool cyclic = false);

    private:
    fs::SDFS* _sd = nullptr;
    std::string _filename = "";
    fs::File _fp;
    bool _is_open;
    bool _initialized{false};
    bool _changed{false};
    std::vector<uint8_t> _block_memory;
};

struct EmulationLayerF::Service {
    Service(uint8_t* memory):
        _memory(memory){}

    uint16_t service_code() const{
        return readBE16(_memory, 2);
    }
    uint16_t service_number() const{
        return (service_code() >> 6) & 0x03FF;
    }
    DesKey des_key() const{
        return DesKey(_memory + 6);
    }

    bool operator<(const Service &r) const{
        return this->service_code() < r.service_code();
    }
    bool operator<(const uint16_t r) const{
        return this->service_code() < r;
    }
    bool operator==(const uint16_t r) const{
        return this->service_code() == r;
    }
    friend bool operator<(const Service &l, const Service &r){
        return l.service_code() < r.service_code();
    }
    friend bool operator<(const uint16_t &l, const Service &r){
        return l < r.service_code();
    }

    private:
    uint8_t* _memory;
};

struct EmulationLayerF::ServiceBlock {
    ServiceBlock(uint8_t* memory):
        _memory(memory){}

    bool read(const uint16_t block_num, uint8_t* buf, const bool cyclic = false) const{
        if(block_count() <= block_num){
            return false;
        }

        if(cyclic){
            const uint16_t index = (cyclic_index() + block_num) % block_count();

            memcpy(buf, _memory + (index << 4), 16);
        }
        else{
            memcpy(buf, _memory + (block_num << 4), 16);
        }
        return false;
    }

    uint16_t service_number() const{
        return readBE16(_memory, 2) & 0x03FF;
    }
    uint16_t block_count() const{
        return (readBE16(_memory, 0) & 0x3FFF) - 1;
    }
    uint16_t cyclic_index() const{
        return readBE16(_memory, 4);
    }

    bool operator<(const ServiceBlock &r) const{
        return this->service_number() < r.service_number();
    }
    bool operator<(const uint16_t r) const{
        return this->service_number() < r;
    }
    bool operator==(const uint16_t r) const{
        return this->service_number() == r;
    }
    friend bool operator<(const ServiceBlock &l, const ServiceBlock &r){
        return l.service_number() < r.service_number();
    }
    friend bool operator<(const uint16_t &l, const ServiceBlock &r){
        return l < r.service_number();
    }

    private:
    uint8_t* _memory;
};

struct EmulationLayerF::Area {
    Area(uint8_t* memory):
        _memory(memory){}

    uint8_t area_code() const{
        return readBE16(_memory, 2);
    }
    uint8_t end_service_code() const{
        return readBE16(_memory, 4);
    }
    DesKey des_key() const{
        return DesKey(_memory + 6);
    }

    bool operator<(const Area &r) const{
        return this->area_code() < r.area_code();
    }
    bool operator<(const uint16_t r) const{
        return this->area_code() < r;
    }
    bool operator==(const uint16_t r) const{
        return this->area_code() == r;
    }
    friend bool operator<(const Area &l, const Area &r){
        return l.area_code() < r.area_code();
    }
    friend bool operator<(const uint16_t l, const Area &r){
        return l < r.area_code();
    }

    private:
    uint8_t* _memory;
};

}  // namespace nfc
}  // namespace m5
#endif
