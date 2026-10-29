/*
 * Wi-Fi Sniffer / Evil Twin & Deauth Detector
 * Waveshare ESP32-S3-Touch-LCD-3.49
 * ------------------------------------------------------------------
 * DEFENSIVE / PASSIVE. Never transmits. Scans 802.11 management frames,
 * lists every nearby access point, and lets you TAP one to lock onto it:
 * the radio stops channel-hopping and listens only on that network's
 * channel. Tap again to go back to full scanning.
 *
 * While locked (or scanning) it also counts deauth/disassoc frames and
 * flags Evil Twins (one SSID on >1 BSSID) in the header.
 *
 * Display driver, touch and LVGL port are Waveshare's vendored files
 * (axs15231b/, touch/, lvgl_port.c, i2c_bsp.c). We build the UI + sniffer.
 * ------------------------------------------------------------------
 */
#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "lvgl.h"

extern "C" {
#include "user_config.h"
#include "i2c_bsp.h"
#include "lvgl_port.h"
#include "lcd_bl_bsp/lcd_bl_pwm_bsp.h"
#include "tca9554/esp_io_expander_tca9554.h"
#include "driver/i2c_master.h"
#include "esp_adc/adc_oneshot.h"
}

// ---- tunables -----------------------------------------------------
// Weighted hop: the busy channels 1/6/11 are revisited often so common APs
// (and your Lolkito on ch11) are caught almost every second; the rest are
// still covered for completeness.
static const uint8_t  CHANNELS[]       = {1, 6, 11, 2, 3, 1, 6, 11, 4, 5,
                                          1, 6, 11, 7, 8, 1, 6, 11, 9, 10,
                                          1, 6, 11, 12, 13};
static const int      NUM_CHANNELS     = sizeof(CHANNELS) / sizeof(CHANNELS[0]);
static const uint32_t CHANNEL_DWELL_MS = 220;   // >= 2 beacon intervals
static const uint32_t DEAUTH_WINDOW_MS = 1000;
static const int      MAX_APS          = 48;
// ------------------------------------------------------------------

struct ApRecord {
  uint8_t  bssid[6];
  char     ssid[33];
  uint8_t  channel;
  int8_t   rssi;
  uint32_t lastSeen;
};
static ApRecord aps[MAX_APS];
static volatile int apCount = 0;

// deauth / evil-twin state
volatile uint32_t g_deauthInWindow = 0;
volatile uint32_t g_deauthRate     = 0;
volatile int      g_evilTwinCount  = 0;
static char       g_evilTwinSsid[33] = {0};

// scan vs lock
static volatile int g_lockChannel = -1;   // -1 = hop all channels, else fixed
static uint8_t      chanIndex     = 0;
static uint32_t     lastHop       = 0;
static uint32_t     windowStart   = 0;

// ---- UI handles ---------------------------------------------------
static lv_obj_t *ui_head;
static lv_obj_t *ui_list;
static lv_obj_t *rowObj[MAX_APS];
static lv_obj_t *rowSsid[MAX_APS];
static lv_obj_t *rowMeta[MAX_APS];
static int       rowCount = 0;
static int       g_selIdx = -1;           // selected row (UI side)
static int8_t    prevRssi[MAX_APS];       // last value shown, to skip redraws
static uint8_t   prevCh[MAX_APS];
static lv_obj_t *ui_batt;                 // battery indicator (top-right)

// ---- power / battery ---------------------------------------------
static const int POWER_BTN_PIN = 16;      // power button, active low
static esp_io_expander_handle_t g_ioexp = NULL;   // TCA9554; PIN_NUM_6 = power hold
static adc_oneshot_unit_handle_t g_adc = NULL;
static float g_battVolts = 0;
static int   g_battPct   = 0;

static const lv_color_t COL_BG    = LV_COLOR_MAKE(0x0E, 0x12, 0x18);
static const lv_color_t COL_HEAD  = LV_COLOR_MAKE(0x16, 0x1D, 0x27);
static const lv_color_t COL_ROW   = LV_COLOR_MAKE(0x1B, 0x22, 0x2D);
static const lv_color_t COL_SEL   = LV_COLOR_MAKE(0x1F, 0x6F, 0xE5);
static const lv_color_t COL_TEXT  = LV_COLOR_MAKE(0xF2, 0xF5, 0xF8);
static const lv_color_t COL_MUTED = LV_COLOR_MAKE(0x8A, 0x97, 0xA6);
static const lv_color_t COL_RED   = LV_COLOR_MAKE(0xE5, 0x3A, 0x3A);

static bool macEq(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }
static void macStr(const uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// ---- row selection ------------------------------------------------
static void applyHighlight() {
  for (int i = 0; i < rowCount; i++) {
    lv_obj_set_style_bg_color(rowObj[i], (i == g_selIdx) ? COL_SEL : COL_ROW, 0);
  }
}

static void rowEventCb(lv_event_t* e) {
  lv_obj_t* row = lv_event_get_target(e);
  int idx = (int)(intptr_t)lv_obj_get_user_data(row) - 1;
  if (idx < 0 || idx >= apCount) return;

  if (g_selIdx == idx) {            // tap selected again -> back to scanning
    g_selIdx = -1;
    g_lockChannel = -1;
  } else {                          // lock onto this network's channel
    g_selIdx = idx;
    g_lockChannel = (aps[idx].channel >= 1 && aps[idx].channel <= 13)
                    ? aps[idx].channel : CHANNELS[chanIndex];
  }
  applyHighlight();
}

// ---- build screen -------------------------------------------------
extern "C" void app_ui_init(void) {
  lv_obj_t* scr = lv_scr_act();
  lv_obj_set_style_bg_color(scr, COL_BG, 0);
  lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

  // Header bar.
  ui_head = lv_label_create(scr);
  lv_obj_set_pos(ui_head, 12, 6);
  lv_obj_set_width(ui_head, 470);
  lv_label_set_long_mode(ui_head, LV_LABEL_LONG_DOT);
  lv_label_set_text(ui_head, "SCANNING...");
  lv_obj_set_style_text_color(ui_head, COL_TEXT, 0);
  lv_obj_set_style_text_font(ui_head, &lv_font_montserrat_20, 0);

  // Battery indicator, top-right.
  ui_batt = lv_label_create(scr);
  lv_obj_set_width(ui_batt, 150);
  lv_obj_set_style_text_align(ui_batt, LV_TEXT_ALIGN_RIGHT, 0);
  lv_obj_align(ui_batt, LV_ALIGN_TOP_RIGHT, -12, 6);
  lv_label_set_text(ui_batt, "-- %");
  lv_obj_set_style_text_color(ui_batt, COL_MUTED, 0);
  lv_obj_set_style_text_font(ui_batt, &lv_font_montserrat_20, 0);

  // Scrollable network list.
  ui_list = lv_obj_create(scr);
  lv_obj_set_size(ui_list, 640, 138);
  lv_obj_set_pos(ui_list, 0, 34);
  lv_obj_set_style_bg_color(ui_list, COL_BG, 0);
  lv_obj_set_style_bg_opa(ui_list, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(ui_list, 0, 0);
  lv_obj_set_style_pad_all(ui_list, 6, 0);
  lv_obj_set_style_pad_row(ui_list, 6, 0);
  lv_obj_set_flex_flow(ui_list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(ui_list, LV_DIR_VER);
}

// Create one row object for AP index i (called under the LVGL lock).
static void makeRow(int i) {
  lv_obj_t* row = lv_obj_create(ui_list);
  lv_obj_set_width(row, LV_PCT(100));
  lv_obj_set_height(row, 36);
  lv_obj_set_style_bg_color(row, COL_ROW, 0);
  lv_obj_set_style_bg_opa(row, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(row, 0, 0);
  lv_obj_set_style_radius(row, 8, 0);
  lv_obj_set_style_pad_hor(row, 12, 0);
  lv_obj_set_style_pad_ver(row, 0, 0);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_user_data(row, (void*)(intptr_t)(i + 1));
  lv_obj_add_event_cb(row, rowEventCb, LV_EVENT_CLICKED, NULL);

  lv_obj_t* ssid = lv_label_create(row);
  lv_obj_set_style_text_color(ssid, COL_TEXT, 0);
  lv_obj_set_style_text_font(ssid, &lv_font_montserrat_20, 0);
  lv_label_set_long_mode(ssid, LV_LABEL_LONG_DOT);
  lv_obj_set_width(ssid, 420);
  lv_label_set_text(ssid, aps[i].ssid);

  lv_obj_t* meta = lv_label_create(row);
  lv_obj_set_style_text_color(meta, COL_MUTED, 0);
  lv_obj_set_style_text_font(meta, &lv_font_montserrat_14, 0);
  lv_label_set_text(meta, "");

  rowObj[i] = row; rowSsid[i] = ssid; rowMeta[i] = meta;
}

// ---- sniffer ------------------------------------------------------
static void handleBeacon(const uint8_t* payload, int len, int8_t rssi) {
  if (len < 38) return;
  const uint8_t* bssid = payload + 16;

  char ssid[33] = {0};
  uint8_t channel = 0;
  int i = 36;
  while (i + 2 <= len) {
    uint8_t tag = payload[i], tlen = payload[i + 1];
    if (i + 2 + tlen > len) break;
    if (tag == 0 && tlen <= 32) { memcpy(ssid, payload + i + 2, tlen); ssid[tlen] = 0; }
    else if (tag == 3 && tlen >= 1) { channel = payload[i + 2]; }
    i += 2 + tlen;
  }
  if (ssid[0] == 0) return;

  for (int k = 0; k < apCount; k++) {
    if (strcmp(aps[k].ssid, ssid) == 0 && strcmp(ssid, "(hidden)") != 0 && !macEq(aps[k].bssid, bssid)) {
      g_evilTwinCount++;
      strncpy(g_evilTwinSsid, ssid, 32); g_evilTwinSsid[32] = 0;
      break;
    }
  }
  for (int k = 0; k < apCount; k++) {
    if (macEq(aps[k].bssid, bssid)) {
      aps[k].rssi = rssi; aps[k].lastSeen = millis();
      if (channel) aps[k].channel = channel;
      return;
    }
  }
  if (apCount < MAX_APS) {
    ApRecord& r = aps[apCount];
    memcpy(r.bssid, bssid, 6);
    strncpy(r.ssid, ssid, 32); r.ssid[32] = 0;
    r.channel = channel; r.rssi = rssi; r.lastSeen = millis();
    apCount++;              // publish only after the record is fully written
  }
}

static void snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  auto* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t subtype = (p[0] >> 4) & 0x0F;
  if (subtype == 0x0C || subtype == 0x0A) g_deauthInWindow++;   // deauth/disassoc
  else if (subtype == 0x08 || subtype == 0x05)                  // beacon / probe-resp
    handleBeacon(p, len, pkt->rx_ctrl.rssi);
}

static void startSniffer() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
}

// ---- UI refresh ---------------------------------------------------
static void refreshUi() {
  char buf[96];
  int count = apCount;

  lvgl_port_lock(-1);

  for (int i = rowCount; i < count; i++) {
    makeRow(i);
    prevRssi[i] = 0; prevCh[i] = 0;
    char b[18]; macStr(aps[i].bssid, b);
    Serial.printf("[AP+] %-24s ch%-2d %4ddBm %s\n", aps[i].ssid, aps[i].channel, aps[i].rssi, b);
    rowCount++;
  }

  // Update only rows whose rssi/channel actually changed -> fewer redraws.
  for (int i = 0; i < rowCount; i++) {
    if (aps[i].rssi != prevRssi[i] || aps[i].channel != prevCh[i]) {
      snprintf(buf, sizeof(buf), "ch%-2d  %ddBm", aps[i].channel, aps[i].rssi);
      lv_label_set_text(rowMeta[i], buf);
      prevRssi[i] = aps[i].rssi; prevCh[i] = aps[i].channel;
    }
  }

  int shownCh = (g_lockChannel >= 1) ? g_lockChannel : CHANNELS[chanIndex];
  if (g_selIdx >= 0 && g_selIdx < count) {
    snprintf(buf, sizeof(buf), "LISTEN  \"%s\"  ch%d   deauth/s %lu",
             aps[g_selIdx].ssid, shownCh, (unsigned long)g_deauthRate);
  } else {
    snprintf(buf, sizeof(buf), "SCANNING ch%d   APs %d   deauth/s %lu",
             shownCh, count, (unsigned long)g_deauthRate);
  }
  // The panel needs a full-frame flush for ANY invalidation, so only touch a
  // label when its text/colour really changed.
  static char prevHead[96] = {0};
  static bool prevHeadRed = false;
  if (strcmp(prevHead, buf) != 0) {
    lv_label_set_text(ui_head, buf);
    strncpy(prevHead, buf, sizeof(prevHead) - 1);
  }
  bool headRed = g_deauthRate >= 5;
  if (headRed != prevHeadRed) {
    lv_obj_set_style_text_color(ui_head, headRed ? COL_RED : COL_TEXT, 0);
    prevHeadRed = headRed;
  }

  static char prevBatt[32] = {0};
  static bool prevBattRed = false;
  snprintf(buf, sizeof(buf), "%d%%  %.2fV", g_battPct, g_battVolts);
  if (strcmp(prevBatt, buf) != 0) {
    lv_label_set_text(ui_batt, buf);
    strncpy(prevBatt, buf, sizeof(prevBatt) - 1);
  }
  bool battRed = g_battPct <= 15;
  if (battRed != prevBattRed) {
    lv_obj_set_style_text_color(ui_batt, battRed ? COL_RED : COL_MUTED, 0);
    prevBattRed = battRed;
  }

  lvgl_port_unlock();
}

// ---- power / battery ----------------------------------------------
static void powerInit() {
  // TCA9554 lives on I2C bus 0 (created by i2c_master_Init). PIN6 is the power
  // latch: drive it high to keep the board running on battery.
  i2c_master_bus_handle_t bus = NULL;
  if (i2c_master_get_bus_handle(0, &bus) == ESP_OK && bus) {
    if (esp_io_expander_new_i2c_tca9554(bus, ESP_IO_EXPANDER_I2C_TCA9554_ADDRESS_000, &g_ioexp) == ESP_OK) {
      esp_io_expander_set_dir(g_ioexp, IO_EXPANDER_PIN_NUM_6, IO_EXPANDER_OUTPUT);
      esp_io_expander_set_level(g_ioexp, IO_EXPANDER_PIN_NUM_6, 1);   // hold power ON
    }
  }
  // Battery sense on ADC1 channel 3 (GPIO4) through a /3 divider.
  adc_oneshot_unit_init_cfg_t uc = {};
  uc.unit_id = ADC_UNIT_1;
  adc_oneshot_new_unit(&uc, &g_adc);
  adc_oneshot_chan_cfg_t cc = {};
  cc.atten = ADC_ATTEN_DB_12;
  cc.bitwidth = ADC_BITWIDTH_12;
  adc_oneshot_config_channel(g_adc, ADC_CHANNEL_3, &cc);

  pinMode(POWER_BTN_PIN, INPUT_PULLUP);
}

static void readBattery() {
  if (!g_adc) return;
  int acc = 0, n = 0;
  for (int i = 0; i < 8; i++) { int r = 0; if (adc_oneshot_read(g_adc, ADC_CHANNEL_3, &r) == ESP_OK) { acc += r; n++; } }
  if (!n) return;
  g_battVolts = ((float)(acc / n) * 3.3f / 4096.0f) * 3.0f;   // vendor formula
  int pct = (int)((g_battVolts - 3.30f) / (4.20f - 3.30f) * 100.0f);  // rough LiPo map
  g_battPct = pct < 0 ? 0 : (pct > 100 ? 100 : pct);
}

static void powerOff() {
  if (!g_ioexp) return;
  esp_io_expander_set_level(g_ioexp, IO_EXPANDER_PIN_NUM_6, 0);  // cut the latch (battery only)
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n== Wi-Fi Sniffer / Evil Twin Detector ==");

  i2c_master_Init();
  lvgl_port_init();
  lcd_bl_pwm_bsp_init(LCD_PWM_MODE_255);
  powerInit();

  startSniffer();
  windowStart = millis();
  lastHop = millis();
}

void loop() {
  uint32_t now = millis();
  static int applied = -1;

  // Power button (GPIO16, active low): hold ~1.2s to power off (battery only).
  static bool pbDown = false; static uint32_t pbAt = 0; static bool pbOff = false;
  bool pb = (digitalRead(POWER_BTN_PIN) == LOW);
  if (pb && !pbDown) { pbDown = true; pbAt = now; pbOff = false; }
  else if (pb && pbDown && !pbOff && now - pbAt >= 1200) {
    lvgl_port_lock(-1);
    lv_label_set_text(ui_head, "POWERING OFF");
    lv_obj_set_style_text_color(ui_head, COL_RED, 0);
    lvgl_port_unlock();
    delay(400);
    powerOff();
    pbOff = true;
  } else if (!pb && pbDown) { pbDown = false; }

  if (g_lockChannel >= 1) {                       // locked on a chosen network
    if (applied != g_lockChannel) {
      esp_wifi_set_channel(g_lockChannel, WIFI_SECOND_CHAN_NONE);
      applied = g_lockChannel;
    }
  } else if (now - lastHop >= CHANNEL_DWELL_MS) {  // scanning: hop channels
    chanIndex = (chanIndex + 1) % NUM_CHANNELS;
    esp_wifi_set_channel(CHANNELS[chanIndex], WIFI_SECOND_CHAN_NONE);
    applied = -1;
    lastHop = now;
  }

  if (now - windowStart >= DEAUTH_WINDOW_MS) {   // rate window: 1s
    g_deauthRate = g_deauthInWindow;
    g_deauthInWindow = 0;
    windowStart = now;
    readBattery();
    Serial.printf("[BATT] %d%% %.2fV\n", g_battPct, g_battVolts);

    int shownCh = (g_lockChannel >= 1) ? g_lockChannel : CHANNELS[chanIndex];
    if (g_selIdx >= 0)
      Serial.printf("[LISTEN] \"%s\" ch%d  deauth/s=%lu  APs=%d  evilTwin=%d\n",
                    aps[g_selIdx].ssid, shownCh, (unsigned long)g_deauthRate, apCount, g_evilTwinCount);
    else
      Serial.printf("[SCAN] ch%d  APs=%d  deauth/s=%lu  evilTwin=%d\n",
                    shownCh, apCount, (unsigned long)g_deauthRate, g_evilTwinCount);
    if (g_deauthRate >= 5) Serial.printf("[!! DEAUTH] %lu frames/s\n", (unsigned long)g_deauthRate);
  }

  static uint32_t lastUi = 0;                    // UI refresh: ~3x/s, snappy
  if (now - lastUi >= 300) { refreshUi(); lastUi = now; }

  static uint32_t lastDump = 0;                  // full AP table every 5s
  if (now - lastDump >= 5000) {
    lastDump = now;
    int n = apCount;
    Serial.printf("---- AP TABLE (%d) ----\n", n);
    for (int i = 0; i < n; i++) {
      char b[18]; macStr(aps[i].bssid, b);
      Serial.printf("  [%02d] %-24s ch%-2d %4ddBm %s\n", i, aps[i].ssid, aps[i].channel, aps[i].rssi, b);
    }
  }

  delay(5);
}
