/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  NFC-F Emulation mode
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <vector>
#include <SPI.h>
#include <SD.h>

// ========== CoreS3 SD Card Correct Pin Definitions ==========
#define SD_SPI_CS_PIN    4
#define SD_SPI_SCK_PIN  36
#define SD_SPI_MISO_PIN 35
#define SD_SPI_MOSI_PIN 37

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
#endif

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message "Choose UnitNFC"
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_CAP_CC1101)
#pragma message "Choose CapCC1101NFC"
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
#else
#error Choose unit please!
#endif
m5::nfc::EmulationLayerF emu_f{unit};

PICC picc{}, picc2{};

constexpr Type type{Type::FeliCaStandard};
// constexpr uint8_t IDm[8] = {0x01, 0x2E, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};  // See also SONY specification
// documents
constexpr uint8_t IDm[8] = {0x01, 0x2E, 0x50, 0xE5, 0x3C, 0x4B, 0x4F, 0x29};
constexpr uint8_t IDm2[8] = {0xff, 0x2E, 0x50, 0xE5, 0x3C, 0x4B, 0x4F, 0x29};
constexpr uint8_t PMm[8] = {0x04, 0x01, 0x84, 0x84, 0x8F, 0x89, 0x94, 0xFF};  // See also SONY specification documents
constexpr uint8_t IDi[8] = "abcdefg";
constexpr uint8_t IDi2[8] = "hijklmn";
constexpr uint8_t PMi[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

using namespace m5::nfc;

std::vector<EmulationLayerF::Area> areas = {
    EmulationLayerF::Area(0x0000, 0xFFFE, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x0040, 0x07FF, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x0800, 0x0FBF, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x0FC0, 0x7FFF, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x1000, 0x17BF, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x17C0, 0x7FFF, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3)),
    EmulationLayerF::Area(0x1800, 0x1A3F, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3))
};

const uint16_t picc_memory = 0;

std::vector<EmulationLayerF::Service> services = {
    // Service 1: 4 Blocks
    EmulationLayerF::Service(0x0048, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 4, picc_memory + 0),
    EmulationLayerF::Service(0x004A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 4, picc_memory + 0),

    // Service 2: 1 Block
    EmulationLayerF::Service(0x0088, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 4),
    EmulationLayerF::Service(0x008B, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 4),

    // Service 32: 1 Block
    EmulationLayerF::Service(0x0810, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 5),
    EmulationLayerF::Service(0x0812, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 5),
    EmulationLayerF::Service(0x0816, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 5),

    // Service 33: 1 Block
    EmulationLayerF::Service(0x0850, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 6),
    EmulationLayerF::Service(0x0852, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 6),
    EmulationLayerF::Service(0x0856, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 6),

    // Service 34: 1 Block
    EmulationLayerF::Service(0x0890, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 7),
    EmulationLayerF::Service(0x0892, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 7),
    EmulationLayerF::Service(0x0896, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 1, picc_memory + 7),

    // Service 35: 3 Blocks
    EmulationLayerF::Service(0x08C8, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 8),
    EmulationLayerF::Service(0x08CA, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 8),

    // Service 36: 20 Blocks
    EmulationLayerF::Service(0x090C, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 20, picc_memory + 11),
    EmulationLayerF::Service(0x090F, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 20, picc_memory + 11),

    // Service 64: 10 Blocks
    EmulationLayerF::Service(0x1008, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 10, picc_memory + 31),
    EmulationLayerF::Service(0x100A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 10, picc_memory + 31),

    // Service 65: 3 Blocks
    EmulationLayerF::Service(0x1048, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 41),
    EmulationLayerF::Service(0x104A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 41),

    // Service 66: 3 Blocks
    EmulationLayerF::Service(0x108C, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 44),
    EmulationLayerF::Service(0x108F, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 3, picc_memory + 44),

    // Service 67: 2 Blocks
    EmulationLayerF::Service(0x10C8, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 47),
    EmulationLayerF::Service(0x10CB, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 47),

    // Service 68: 2 Blocks
    EmulationLayerF::Service(0x1108, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 49),
    EmulationLayerF::Service(0x110A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 49),

    // Service 69: 2 Blocks
    EmulationLayerF::Service(0x1148, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 51),
    EmulationLayerF::Service(0x114A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 2, picc_memory + 51),

    // Service 96: 4 Blocks
    EmulationLayerF::Service(0x1808, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 4, picc_memory + 53),
    EmulationLayerF::Service(0x180A, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 4, picc_memory + 53),

    // Service 97: 36 Blocks
    EmulationLayerF::Service(0x1848, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 36, picc_memory + 57),
    EmulationLayerF::Service(0x184B, EmulationLayerF::DesKey(0xaaaaaaaaaaaaaaaa, 3), 36, picc_memory + 57),
};

EmulationLayerF::DesKey system_key(0x0123456789abcdef, 3);

constexpr uint16_t color_table[] = {
    //  None,      Off,     Idle,     Ready,   Active,      Halt };
    TFT_BLACK, TFT_RED, TFT_BLUE, TFT_YELLOW, TFT_GREEN, TFT_MAGENTA};
constexpr const char* state_table[] = {"-", "O", "I", "R", "A", "H"};

}  // namespace

m5::nfc::EmulationLayerF::SDStorage storage;

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    // load sd

  // ========== SD Card Initialization (Using Correct Pins) ==========
    SPI.begin(SD_SPI_SCK_PIN, SD_SPI_MISO_PIN, SD_SPI_MOSI_PIN, SD_SPI_CS_PIN);

    if (!SD.begin(SD_SPI_CS_PIN, SPI, 25000000)) {
        M5.Display.println("SD card not detected");
        while (1);
    } else {
        M5.Display.println("SD card detected");
    }
    delay(1000);

    storage.begin(SD, "/FeliCa.bin");

    uint8_t buf[17];
    buf[16] = 0x00;

    storage.open();
    storage.read(0, buf);
    storage.close();

    // Emulation settings
    auto cfg      = unit.config();
    cfg.emulation = true;
    cfg.mode      = NFC::F;
    unit.config(cfg);

    bool unit_ready{};
#if defined(USING_UNIT_NFC)
    //unit_ready = m5::unit::wiring::addI2C(Units, unit, 0, m5::unit::wiring::NessoPort::PortA) && Units.begin();
    unit_ready = Units.add(unit, M5.In_I2C) && Units.begin();
#elif defined(USING_CAP_CC1101)
    // SPI mode 1 (CPOL=0, CPHA=1). Use literal so this builds in ESP-IDF native too
    // (Arduino's SPI_MODE1 is not defined there).
    unit_ready = m5::unit::wiring::addSPI(Units, unit, 10000000, 1) && Units.begin();
#endif
    if (!unit_ready) {
        M5_LOGE("Failed to begin");
        m5::unit::wiring::failStop();
    }
    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font2);

    //
    lcd.startWrite();
    lcd.fillScreen(TFT_RED);
    if (picc.emulate(type, IDm, PMm, 0x0003) && picc2.emulate(type, IDm2, PMm, 0xFE00)) {
        const std::vector<EmulationLayerF::Emulator> emulators ={
            EmulationLayerF::Emulator(
            picc,
            storage,
            IDi,
            PMi,
            system_key,
            areas,
            services
        ), EmulationLayerF::Emulator(
            picc2,
            storage,
            IDi2,
            PMi,
            system_key,
            areas,
            services
        )};

        if (emu_f.begin(emulators)) {
            lcd.fillScreen(TFT_DARKGREEN);
            lcd.setCursor(0, 16);
            const auto& e_picc = emu_f.emulators()[0].emulatePICC();
            M5.Log.printf("Emulation:%s %s:%s SC:%02X\n", e_picc.typeAsString().c_str(), e_picc.idmAsString().c_str(),
                        e_picc.pmmAsString().c_str(), e_picc.emulation_sc);
            lcd.printf("Emulation: %s\nIDm: %s\nPMm: %s\nSC: %02X\n", e_picc.typeAsString().c_str(),
                        e_picc.idmAsString().c_str(),
                        e_picc.pmmAsString().c_str(),
                        e_picc.emulation_sc);
            lcd.printf("IDi: ");
            for(uint8_t i = 0; i < 8; i++){
                lcd.printf("%02X", emu_f.emulators()[0].idi[i]);
            }
            lcd.printf("\nPMi: ");
            for(uint8_t i = 0; i < 8; i++){
                lcd.printf("%02X", emu_f.emulators()[0].pmi[i]);
            }
            lcd.printf("\n");
        } else {
            M5_LOGE("Start");
        }
    } else {
        M5_LOGE("PICC");
    }
    lcd.fillRect(0, 0, 32, 16, color_table[0]);
    lcd.drawString(state_table[0], 0, 0);
    lcd.endWrite();
}

void loop()
{
    M5.update();
    Units.update();
    emu_f.update();  // Need call in loop

    static EmulationLayerF::State latest{};
    auto state = emu_f.state();
    if (latest != state) {
        latest = state;
        lcd.startWrite();
        lcd.fillRect(0, 0, 32, 16, color_table[m5::stl::to_underlying(state)]);
        lcd.drawString(state_table[m5::stl::to_underlying(state)], 0, 0);
        lcd.endWrite();
    }
}

#if !defined(ARDUINO)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>

#if CONFIG_FREERTOS_UNICORE
static inline void feedIdleTaskPeriodically(void)
{
    constexpr uint32_t FEED_INTERVAL_MS   = 2000;
    constexpr TickType_t FEED_SLEEP_TICKS = pdMS_TO_TICKS(5);
    static uint32_t s_next_feed_ms        = 0;
    const uint32_t now_ms                 = static_cast<uint32_t>(esp_timer_get_time() / 1000);
    if (now_ms >= s_next_feed_ms) {
        s_next_feed_ms = now_ms + FEED_INTERVAL_MS;
        vTaskDelay(FEED_SLEEP_TICKS);
    }
}
#endif

extern "C" void app_main(void)
{
    setup();
    for (;;) {
#if CONFIG_FREERTOS_UNICORE
        feedIdleTaskPeriodically();
#endif
        loop();
    }
}
#endif
