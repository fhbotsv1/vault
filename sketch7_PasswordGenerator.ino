
#include <Arduino.h>
#include <Wire.h>
#include <LovyanGFX.hpp>
#include <Adafruit_Fingerprint.h>
#include <SD_MMC.h>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_sleep.h>
#include <mbedtls/gcm.h>
#include <WiFi.h>
#include <WebServer.h>
#include <HijelHID_BLEKeyboard.h>
#include <qrcode.h>  // Install the "QRCode" library by Richard Moore (ricmoo)

// =================================================
// ES3C28P PASSWORD VAULT - STAGE 7
// AOA Wi-Fi hotspot: authenticated add-only web entry; no account viewing/deletion over Wi-Fi
// =================================================

// TFT: ILI9341V, 240 x 320
#define TFT_SCLK 12
#define TFT_MOSI 11
#define TFT_MISO 13
#define TFT_CS   10
#define TFT_DC   46
#define TFT_BL   45

// FT6336G capacitive touchscreen
#define TOUCH_SDA  16
#define TOUCH_SCL  15
#define TOUCH_RST  18
#define TOUCH_INT  17
#define TOUCH_ADDR 0x38

// R307S on UART1
#define FP_RX 21
#define FP_TX 14
#define TOUCH_PIN 3

HardwareSerial FingerSerial(1);
Adafruit_Fingerprint finger(&FingerSerial);

#define BATTERY_ADC_PIN 9
#define BATTERY_VOLTAGE_MULTIPLIER 1.99f

float batteryVoltage = 0.0f;
int batteryPercentage = 0;

float readBatteryVoltage() {
  uint32_t total = 0;

  // Average 20 ADC readings
  for (int i = 0; i < 20; i++) {
    total += analogReadMilliVolts(BATTERY_ADC_PIN);
  }

  float adcVoltage = (total / 20.0f) / 1000.0f;

  return adcVoltage * BATTERY_VOLTAGE_MULTIPLIER;
}

// Approximate voltage-to-percentage conversion.
// Values are interpolated between the reference points.
int getBatteryPercentage(float voltage) {
  const float voltagePoints[] = {
    3.30f, 3.50f, 3.60f, 3.70f, 3.80f,
    3.90f, 4.00f, 4.10f, 4.20f
  };

  const int percentagePoints[] = {
    0, 10, 20, 35, 50, 65, 80, 90, 100
  };

  if (voltage <= voltagePoints[0]) return 0;
  if (voltage >= voltagePoints[8]) return 100;

  for (int i = 0; i < 8; i++) {
    if (voltage <= voltagePoints[i + 1]) {
      float fraction =
        (voltage - voltagePoints[i]) /
        (voltagePoints[i + 1] - voltagePoints[i]);

      return percentagePoints[i] +
        (int)((percentagePoints[i + 1] -
               percentagePoints[i]) * fraction + 0.5f);
    }
  }

  return 0;
}

void updateBatteryReading() {
  batteryVoltage = readBatteryVoltage();
  batteryPercentage = getBatteryPercentage(batteryVoltage);

  Serial.printf(
    "Battery: %.2f V | %d%%\n",
    batteryVoltage,
    batteryPercentage
  );
}

// BLE HID keyboard: sends credentials to the currently focused field on a paired device.
HijelHID_BLEKeyboard bleKeyboard;
bool bleKeyboardStarted = false;

const char DEV_PIN[] = "1234";  // Development only

// ----- Encrypted storage prototype -----
// Stage 5 supports multiple encrypted records; existing legacy record is migrated on save.
static const char *VAULT_FILE = "/vault.dat";
static const char *VAULT_TEMP = "/vault.tmp";
static const char *VAULT_BACKUP = "/vault.bak";
static const char *VAULT_REPAIR_BACKUP = "/vault.pre-repair.bak";
static const char *VAULT_REPAIR_TEMP = "/vault.repair.tmp";
static const char *VAULT_REPAIR_OLD = "/vault.repair.old";
static const uint8_t VAULT_MAGIC[4] = {'V', 'L', 'T', '2'};
static const size_t VAULT_KEY_SIZE = 32;
static const size_t VAULT_NONCE_SIZE = 12;
static const size_t VAULT_TAG_SIZE = 16;
static const size_t VAULT_HEADER_SIZE = 20;
static const size_t MAX_VAULT_PLAINTEXT = 2048;
static const uint8_t MAX_ACCOUNTS = 8;

struct VaultAccount {
  String site;
  String user;
  String password;
};
VaultAccount vaultAccounts[MAX_ACCOUNTS];
uint8_t vaultAccountCount = 0;
int selectedAccount = 0;
String editSite = "";
String editUser = "";
String editPassword = "";
char generatedPassword[11] = {0};
bool generatedPasswordReady = false;
uint8_t editField = 0; // 0=site, 1=username, 2=password
bool keyboardShift = false;
bool keyboardSymbols = false;
bool editingExistingAccount = false;
bool passwordVisible = false;
String serialLineBuffer = "";

uint8_t vaultKey[VAULT_KEY_SIZE];
bool vaultStorageReady = false;
bool accountLoaded = false;
// True when /vault.dat exists but its structure cannot be read as VLT2.
bool vaultFileInvalid = false;
String accountSite = "";
String accountUser = "";
String accountPassword = "";

const uint32_t AUTO_LOCK_MS = 60000;
const uint32_t FP_POLL_MS = 100;
const uint8_t MAX_FP_FAILURES = 3;

// ----- Display configuration -----

class LGFX : public lgfx::LGFX_Device {
  lgfx::Panel_ILI9341 panel;
  lgfx::Bus_SPI bus;

public:
  LGFX() {
    auto b = bus.config();

    b.spi_host = SPI2_HOST;
    b.spi_mode = 0;
    b.freq_write = 40000000;
    b.freq_read = 16000000;
    b.spi_3wire = false;
    b.use_lock = true;
    b.dma_channel = SPI_DMA_CH_AUTO;
    b.pin_sclk = TFT_SCLK;
    b.pin_mosi = TFT_MOSI;
    b.pin_miso = TFT_MISO;
    b.pin_dc = TFT_DC;

    bus.config(b);
    panel.setBus(&bus);

    auto p = panel.config();
    p.pin_cs = TFT_CS;
    p.pin_rst = -1;
    p.pin_busy = -1;
    p.memory_width = 240;
    p.memory_height = 320;
    p.panel_width = 240;
    p.panel_height = 320;
    p.offset_x = 0;
    p.offset_y = 0;
    p.offset_rotation = 0;
    p.dummy_read_pixel = 8;
    p.dummy_read_bits = 1;
    p.readable = true;
    p.invert = true;
    p.rgb_order = false;
    p.dlen_16bit = false;
    p.bus_shared = false;

    panel.config(p);
    setPanel(&panel);
  }
};

LGFX lcd;

// ----- Screens -----

enum Screen {
  FINGERPRINT_SCREEN,
  PIN_SCREEN,
  HOME_SCREEN,
  MY_ACCOUNTS_SCREEN,
  ACCOUNT_DETAIL_SCREEN,
  ADD_ACCOUNT_SCREEN,
  DELETE_CONFIRM_SCREEN,
  AOA_QR_SCREEN,
  GENERATE_SCREEN
};

Screen currentScreen = FINGERPRINT_SCREEN;

// Two-step confirmation prevents accidental shutdown from the lock screen.
bool powerOffConfirm = false;

// ----- AOA (Add Over Air) local web interface -----
// Change this WPA2 passphrase before using outside a controlled prototype.
static const char *AOA_SSID = "ES3C28P-AOA";
static const char *AOA_AP_PASSWORD = "VaultAOA-7Q4N"; // 8+ characters required
WebServer aoaServer(80);
bool aoaActive = false;
IPAddress aoaAuthenticatedIP(0, 0, 0, 0);
uint32_t aoaSessionUntil = 0;
uint32_t aoaPinLockoutUntil = 0;
uint8_t aoaBadPinAttempts = 0;
const uint32_t AOA_SESSION_MS = 5UL * 60UL * 1000UL;
const uint32_t AOA_LOCKOUT_MS = 30UL * 1000UL;

// ----- State -----

String enteredPIN = "";
String statusMessage = "";

uint32_t statusUntil = 0;
uint32_t lastActivity = 0;
uint32_t lastFingerprintPoll = 0;

uint8_t fingerprintFailures = 0;

bool touchAvailable = false;
bool fingerDown = false;
bool fingerprintReady = false;

// Prevent repeatedly scanning the same finger
// until it has been removed from the sensor.
bool fingerprintWaitingForRemoval = false;

// ----- Colours -----

uint16_t BG, PANEL, WHITE, MUTED;
uint16_t CYAN, RED, GREEN, BORDER;

// ----- Forward declarations -----

void drawFingerprintScreen();
void drawPINScreen();
void drawHomeScreen();
void drawAOAQRScreen();
void handleAOAQRScreenTouch(uint16_t x, uint16_t y);
void lockVault();
void setStatus(const char *message, uint32_t duration = 1800);
void unlockVault();
void drawAccountsScreen();
void drawAccountDetailScreen();
void pasteCredentialOverBLE(const String &credential, const char *label);
void drawAddAccountScreen();
void drawGenerateScreen();
void handleGenerateTouch(uint16_t x, uint16_t y);
void handleAddAccountTouch(uint16_t x, uint16_t y);
bool initVaultStorage();
bool saveDemoAccount();
bool loadVaultAccount();
bool loadVaultAccounts();
bool saveAllAccounts();
void processSerialEntry();
void startAOA();
void stopAOA();
void serviceAOA();
void handleAOARoot();
void handleAOALogin();
void handleAOAAdd();
void handleAOAPing();
void handleAOANotFound();
bool aoaClientAuthenticated();
String aoaPage(const String &body, const String &title = "AOA - Add Over Air");
bool validAOAField(const String &value, size_t maxLen);

// =================================================
// ENCRYPTED MICROSD STORAGE (LEGACY + MULTI-ACCOUNT FORMAT)
// =================================================

static void writeU32LE(uint8_t *p, uint32_t n) {
  p[0] = n & 0xFF;
  p[1] = (n >> 8) & 0xFF;
  p[2] = (n >> 16) & 0xFF;
  p[3] = (n >> 24) & 0xFF;
}

static uint32_t readU32LE(const uint8_t *p) {
  return (uint32_t)p[0] |
         ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

bool initVaultStorage() {
  // Board's confirmed SDIO pins: CLK 38, CMD 40, D0 39.
  SD_MMC.setPins(38, 40, 39);
  if (!SD_MMC.begin("/sdcard", true, false)) {
    Serial.println("Vault storage: microSD mount failed.");
    return false;
  }

  Preferences prefs;
  if (!prefs.begin("vaultkey", false)) {
    Serial.println("Vault storage: cannot open NVS key namespace.");
    return false;
  }

  size_t keyLength = prefs.getBytesLength("aeskey");
  if (keyLength == VAULT_KEY_SIZE) {
    size_t got = prefs.getBytes("aeskey", vaultKey, VAULT_KEY_SIZE);
    prefs.end();
    if (got != VAULT_KEY_SIZE) {
      Serial.println("Vault storage: cannot read AES key.");
      return false;
    }
    Serial.println("Vault storage: existing AES key loaded from NVS.");
    return true;
  }

  if (keyLength != 0) {
    prefs.end();
    Serial.println("Vault storage: unexpected key length; refusing to overwrite.");
    return false;
  }

  // Create a random key only if one is not already present.
  esp_fill_random(vaultKey, sizeof(vaultKey));
  size_t wrote = prefs.putBytes("aeskey", vaultKey, sizeof(vaultKey));
  prefs.end();

  if (wrote != sizeof(vaultKey)) {
    memset(vaultKey, 0, sizeof(vaultKey));
    Serial.println("Vault storage: failed to save AES key.");
    return false;
  }

  Serial.println("Vault storage: new AES key created in NVS.");
  return true;
}

static bool decodeVaultFile(const char *path, bool allowKnownAnomaly, String &decoded, bool &hasAnomaly);

bool saveEncryptedPayload(const uint8_t *plain, size_t plainLen) {
  if (!vaultStorageReady || !plain || plainLen == 0 || plainLen > MAX_VAULT_PLAINTEXT) {
    return false;
  }

  uint8_t nonce[VAULT_NONCE_SIZE];
  uint8_t tag[VAULT_TAG_SIZE];
  uint8_t lenBytes[4];
  uint8_t aad[8];
  uint8_t *cipher = new uint8_t[plainLen];
  if (!cipher) return false;

  esp_fill_random(nonce, sizeof(nonce));
  writeU32LE(lenBytes, (uint32_t)plainLen);
  memcpy(aad, VAULT_MAGIC, 4);
  memcpy(aad + 4, lenBytes, 4);

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, vaultKey, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
      &ctx, MBEDTLS_GCM_ENCRYPT, plainLen,
      nonce, sizeof(nonce), aad, sizeof(aad),
      plain, cipher, sizeof(tag), tag
    );
  }
  mbedtls_gcm_free(&ctx);

  if (rc != 0) {
    memset(cipher, 0, plainLen);
    delete[] cipher;
    Serial.printf("Vault storage: AES-GCM encryption error %d.\n", rc);
    return false;
  }

  SD_MMC.remove(VAULT_TEMP);
  File f = SD_MMC.open(VAULT_TEMP, FILE_WRITE);
  if (!f) {
    memset(cipher, 0, plainLen);
    delete[] cipher;
    Serial.println("Vault storage: cannot create temporary file.");
    return false;
  }

  bool ok =
    f.write(VAULT_MAGIC, sizeof(VAULT_MAGIC)) == sizeof(VAULT_MAGIC) &&
    f.write(nonce, sizeof(nonce)) == sizeof(nonce) &&
    f.write(lenBytes, sizeof(lenBytes)) == sizeof(lenBytes) &&
    f.write(cipher, plainLen) == plainLen &&
    f.write(tag, sizeof(tag)) == sizeof(tag);
  f.flush();
  f.close();

  memset(cipher, 0, plainLen);
  delete[] cipher;

  if (!ok) {
    SD_MMC.remove(VAULT_TEMP);
    Serial.println("Vault storage: incomplete write.");
    return false;
  }

  // Authenticate and compare the temporary encrypted file before touching the current vault.
  String verifiedPayload;
  bool verifiedAnomaly = false;
  bool verified = decodeVaultFile(VAULT_TEMP, false, verifiedPayload, verifiedAnomaly) &&
                  !verifiedAnomaly && verifiedPayload.length() == plainLen &&
                  memcmp(verifiedPayload.c_str(), plain, plainLen) == 0;
  verifiedPayload = "";
  if (!verified) {
    SD_MMC.remove(VAULT_TEMP);
    Serial.println("Vault storage: temporary file verification failed; existing vault untouched.");
    return false;
  }

  // Keep previous file until the replacement has been written and authenticated.
  SD_MMC.remove(VAULT_BACKUP);
  bool hadOld = SD_MMC.exists(VAULT_FILE);
  if (hadOld && !SD_MMC.rename(VAULT_FILE, VAULT_BACKUP)) {
    SD_MMC.remove(VAULT_TEMP);
    Serial.println("Vault storage: couldn't preserve previous file.");
    return false;
  }

  if (!SD_MMC.rename(VAULT_TEMP, VAULT_FILE)) {
    if (hadOld) SD_MMC.rename(VAULT_BACKUP, VAULT_FILE);
    Serial.println("Vault storage: couldn't install new file.");
    return false;
  }

  SD_MMC.remove(VAULT_BACKUP);
  return true;
}

// Decode a vault file without changing it. The only accepted anomaly is the
// exact first-byte value observed during diagnosis (0x98 instead of 'V').
static bool decodeVaultFile(const char *path, bool allowKnownAnomaly,
                            String &decoded, bool &hasAnomaly) {
  decoded = "";
  hasAnomaly = false;
  File f = SD_MMC.open(path, FILE_READ);
  if (!f) {
    Serial.printf("Vault repair: cannot open %s for reading.\n", path);
    return false;
  }

  const size_t fileSize = f.size();
  if (fileSize < VAULT_HEADER_SIZE + VAULT_TAG_SIZE ||
      fileSize > VAULT_HEADER_SIZE + MAX_VAULT_PLAINTEXT + VAULT_TAG_SIZE) {
    f.close();
    Serial.printf("Vault repair: %s has invalid size %u.\n", path, (unsigned)fileSize);
    return false;
  }

  uint8_t magic[4] = {0};
  uint8_t nonce[VAULT_NONCE_SIZE] = {0};
  uint8_t lenBytes[4] = {0};
  uint8_t tag[VAULT_TAG_SIZE] = {0};
  bool ok = f.read(magic, sizeof(magic)) == sizeof(magic) &&
            f.read(nonce, sizeof(nonce)) == sizeof(nonce) &&
            f.read(lenBytes, sizeof(lenBytes)) == sizeof(lenBytes);
  if (!ok) {
    f.close();
    Serial.printf("Vault repair: couldn't read header from %s.\n", path);
    return false;
  }

  uint32_t len = readU32LE(lenBytes);
  const bool canonical = memcmp(magic, VAULT_MAGIC, sizeof(magic)) == 0;
  const bool anomaly = magic[0] == 0x98 &&
                       memcmp(magic + 1, VAULT_MAGIC + 1, 3) == 0;
  if ((!canonical && !(allowKnownAnomaly && anomaly)) ||
      len == 0 || len > MAX_VAULT_PLAINTEXT ||
      fileSize != VAULT_HEADER_SIZE + len + VAULT_TAG_SIZE) {
    f.close();
    Serial.printf("Vault repair: %s has an unexpected header or length.\n", path);
    return false;
  }

  uint8_t *cipher = new uint8_t[len];
  uint8_t *plain = new uint8_t[len + 1];
  if (!cipher || !plain) {
    if (cipher) delete[] cipher;
    if (plain) delete[] plain;
    f.close();
    Serial.println("Vault repair: insufficient memory to verify file.");
    return false;
  }

  ok = f.read(cipher, len) == len && f.read(tag, sizeof(tag)) == sizeof(tag);
  f.close();
  if (!ok) {
    memset(cipher, 0, len);
    memset(plain, 0, len + 1);
    delete[] cipher;
    delete[] plain;
    Serial.printf("Vault repair: incomplete read from %s.\n", path);
    return false;
  }

  // The original encryption code authenticated the canonical VLT2 magic as AAD.
  uint8_t aad[8];
  memcpy(aad, VAULT_MAGIC, 4);
  memcpy(aad + 4, lenBytes, 4);

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, vaultKey, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(&ctx, len, nonce, sizeof(nonce),
                                  aad, sizeof(aad), tag, sizeof(tag),
                                  cipher, plain);
  }
  mbedtls_gcm_free(&ctx);
  memset(cipher, 0, len);
  delete[] cipher;

  if (rc != 0) {
    memset(plain, 0, len + 1);
    delete[] plain;
    Serial.printf("Vault repair: AES-GCM authentication failed for %s.\n", path);
    return false;
  }

  plain[len] = '\0';
  decoded = String((char *)plain);
  memset(plain, 0, len + 1);
  delete[] plain;

  bool validPayload = decoded.startsWith("PV2\n");
  if (!validPayload) {
    int first = decoded.indexOf('|');
    int second = first < 0 ? -1 : decoded.indexOf('|', first + 1);
    validPayload = first > 0 && second > first + 1 && second < (int)decoded.length() - 1;
  }
  if (!validPayload) {
    decoded = "";
    Serial.printf("Vault repair: decrypted record structure invalid in %s.\n", path);
    return false;
  }

  hasAnomaly = anomaly;
  return true;
}

static bool copyFileExact(const char *fromPath, const char *toPath) {
  File in = SD_MMC.open(fromPath, FILE_READ);
  if (!in) return false;
  File out = SD_MMC.open(toPath, FILE_WRITE);
  if (!out) {
    in.close();
    return false;
  }

  uint8_t buffer[256];
  bool ok = true;
  while (in.available()) {
    int n = in.read(buffer, sizeof(buffer));
    if (n <= 0 || out.write(buffer, (size_t)n) != (size_t)n) {
      ok = false;
      break;
    }
  }
  out.flush();
  out.close();
  in.close();
  if (!ok) SD_MMC.remove(toPath);
  return ok;
}

static bool filesIdentical(const char *pathA, const char *pathB) {
  File a = SD_MMC.open(pathA, FILE_READ);
  File b = SD_MMC.open(pathB, FILE_READ);
  if (!a || !b) {
    if (a) a.close();
    if (b) b.close();
    return false;
  }
  if (a.size() != b.size()) {
    a.close(); b.close();
    return false;
  }
  uint8_t ba[128], bb[128];
  bool same = true;
  while (a.available() || b.available()) {
    int na = a.read(ba, sizeof(ba));
    int nb = b.read(bb, sizeof(bb));
    if (na != nb || na < 0 || (na > 0 && memcmp(ba, bb, (size_t)na) != 0)) {
      same = false;
      break;
    }
  }
  a.close(); b.close();
  return same;
}

// Repair only the known 0x98 -> 'V' header anomaly. It first validates the
// original, creates and byte-compares a backup, builds a corrected temporary
// file, verifies AES-GCM and record structure on that copy, then swaps files.
// The backup /vault.pre-repair.bak is deliberately retained after success.
static bool repairKnownHeaderAnomaly() {
  if (SD_MMC.exists(VAULT_REPAIR_BACKUP) || SD_MMC.exists(VAULT_REPAIR_OLD)) {
    Serial.println("Vault repair: safety backup/old file already exists; refusing to overwrite it.");
    return false;
  }

  String originalDecoded;
  bool originalHasAnomaly = false;
  if (!decodeVaultFile(VAULT_FILE, true, originalDecoded, originalHasAnomaly) ||
      !originalHasAnomaly) {
    originalDecoded = "";
    Serial.println("Vault repair: original did not pass anomaly validation; no repair made.");
    return false;
  }
  originalDecoded = "";

  if (SD_MMC.exists(VAULT_REPAIR_TEMP)) SD_MMC.remove(VAULT_REPAIR_TEMP);
  if (!copyFileExact(VAULT_FILE, VAULT_REPAIR_BACKUP) ||
      !filesIdentical(VAULT_FILE, VAULT_REPAIR_BACKUP)) {
    SD_MMC.remove(VAULT_REPAIR_BACKUP);
    Serial.println("Vault repair: could not create and verify an exact backup; original untouched.");
    return false;
  }
  Serial.println("Vault repair: exact backup created at /vault.pre-repair.bak.");

  File in = SD_MMC.open(VAULT_FILE, FILE_READ);
  File out = SD_MMC.open(VAULT_REPAIR_TEMP, FILE_WRITE);
  if (!in || !out) {
    if (in) in.close();
    if (out) out.close();
    SD_MMC.remove(VAULT_REPAIR_TEMP);
    Serial.println("Vault repair: could not open source/temp; original untouched.");
    return false;
  }

  int firstByte = in.read();
  bool ok = firstByte == 0x98 && out.write((uint8_t)'V') == 1;
  uint8_t buffer[256];
  while (ok && in.available()) {
    int n = in.read(buffer, sizeof(buffer));
    if (n <= 0 || out.write(buffer, (size_t)n) != (size_t)n) ok = false;
  }
  out.flush();
  out.close();
  in.close();

  String tempDecoded;
  bool tempHasAnomaly = false;
  if (!ok || !decodeVaultFile(VAULT_REPAIR_TEMP, false, tempDecoded, tempHasAnomaly) || tempHasAnomaly) {
    tempDecoded = "";
    SD_MMC.remove(VAULT_REPAIR_TEMP);
    Serial.println("Vault repair: corrected temporary file failed verification; original untouched.");
    return false;
  }
  tempDecoded = "";
  Serial.println("Vault repair: corrected temporary file passed AES-GCM and record validation.");

  if (!SD_MMC.rename(VAULT_FILE, VAULT_REPAIR_OLD)) {
    SD_MMC.remove(VAULT_REPAIR_TEMP);
    Serial.println("Vault repair: couldn't stage original file; original remains in place.");
    return false;
  }
  if (!SD_MMC.rename(VAULT_REPAIR_TEMP, VAULT_FILE)) {
    bool restored = SD_MMC.rename(VAULT_REPAIR_OLD, VAULT_FILE);
    Serial.printf("Vault repair: couldn't install corrected file; restore %s.\n", restored ? "succeeded" : "FAILED - keep SD card unchanged");
    return false;
  }

  String installedDecoded;
  bool installedAnomaly = false;
  bool installedOk = decodeVaultFile(VAULT_FILE, false, installedDecoded, installedAnomaly) && !installedAnomaly;
  installedDecoded = "";
  if (!installedOk) {
    SD_MMC.remove(VAULT_FILE);
    bool restored = SD_MMC.rename(VAULT_REPAIR_OLD, VAULT_FILE);
    Serial.printf("Vault repair: installed file failed final verification; original restore %s.\n", restored ? "succeeded" : "FAILED - keep SD card unchanged");
    return false;
  }

  SD_MMC.remove(VAULT_REPAIR_OLD);
  Serial.println("Vault repair: SUCCESS. /vault.dat is repaired and verified.");
  Serial.println("Vault repair: original retained at /vault.pre-repair.bak.");
  return true;
}

static bool addParsedAccount(const String &line) {
  if (vaultAccountCount >= MAX_ACCOUNTS) return false;
  int first = line.indexOf('|');
  int second = first < 0 ? -1 : line.indexOf('|', first + 1);
  if (first <= 0 || second <= first + 1 || second >= (int)line.length() - 1) return false;
  vaultAccounts[vaultAccountCount].site = line.substring(0, first);
  vaultAccounts[vaultAccountCount].user = line.substring(first + 1, second);
  vaultAccounts[vaultAccountCount].password = line.substring(second + 1);
  vaultAccountCount++;
  return true;
}

bool loadVaultAccounts() {
  vaultAccountCount = 0;
  accountLoaded = false;
  vaultFileInvalid = false;
  accountSite = "";
  accountUser = "";
  accountPassword = "";
  if (!vaultStorageReady) return false;

  String decoded;
  bool hasAnomaly = false;
  if (!decodeVaultFile(VAULT_FILE, true, decoded, hasAnomaly)) {
    vaultFileInvalid = SD_MMC.exists(VAULT_FILE);
    if (!vaultFileInvalid) Serial.println("Vault: no saved account file yet.");
    return false;
  }

  if (hasAnomaly) {
    Serial.println("Vault repair: authenticated anomaly confirmed; starting backed-up repair.");
    if (repairKnownHeaderAnomaly()) {
      String repairedDecoded;
      bool repairedAnomaly = false;
      if (decodeVaultFile(VAULT_FILE, false, repairedDecoded, repairedAnomaly) && !repairedAnomaly) {
        decoded = repairedDecoded;
        Serial.println("Vault repair: repaired record loaded successfully.");
      } else {
        Serial.println("Vault repair: post-repair reload failed; using authenticated original data where possible.");
      }
    } else {
      Serial.println("Vault repair: automatic repair was not completed; authenticated data remains readable.");
    }
  }

  bool parsed = true;
  if (decoded.startsWith("PV2\n")) {
    int pos = 4;
    while (pos < (int)decoded.length() && vaultAccountCount < MAX_ACCOUNTS) {
      int nl = decoded.indexOf('\n', pos);
      if (nl < 0) nl = decoded.length();
      String line = decoded.substring(pos, nl);
      if (line.length() && !addParsedAccount(line)) { parsed = false; break; }
      pos = nl + 1;
    }
    if (vaultAccountCount == 0) parsed = false;
  } else {
    parsed = addParsedAccount(decoded); // existing legacy single-record file
  }
  decoded = "";
  if (!parsed || vaultAccountCount == 0) {
    vaultAccountCount = 0;
    vaultFileInvalid = true;
    Serial.println("Vault: decrypted account list is invalid; file preserved.");
    return false;
  }

  if (selectedAccount >= vaultAccountCount) selectedAccount = 0;
  accountSite = vaultAccounts[selectedAccount].site;
  accountUser = vaultAccounts[selectedAccount].user;
  accountPassword = vaultAccounts[selectedAccount].password;
  accountLoaded = true;
  vaultFileInvalid = false;
  Serial.printf("Vault: loaded %u encrypted account(s).\n", vaultAccountCount);
  return true;
}

bool loadVaultAccount() {
  selectedAccount = 0;
  return loadVaultAccounts();
}

bool saveAllAccounts() {
  if (!vaultStorageReady || vaultAccountCount == 0 || vaultAccountCount > MAX_ACCOUNTS) return false;
  String payload = "PV2\n";
  for (uint8_t i = 0; i < vaultAccountCount; i++) {
    const VaultAccount &a = vaultAccounts[i];
    if (!a.site.length() || !a.user.length() || !a.password.length() ||
        a.site.indexOf('|') >= 0 || a.user.indexOf('|') >= 0 || a.password.indexOf('|') >= 0 ||
        a.site.indexOf('\n') >= 0 || a.user.indexOf('\n') >= 0 || a.password.indexOf('\n') >= 0) {
      Serial.println("Vault: refusing invalid account field.");
      return false;
    }
    payload += a.site + "|" + a.user + "|" + a.password + "\n";
  }
  if (payload.length() > MAX_VAULT_PLAINTEXT) {
    Serial.println("Vault: account list is too large.");
    payload = "";
    return false;
  }
  bool ok = saveEncryptedPayload((const uint8_t *)payload.c_str(), payload.length());
  payload = "";
  if (ok) {
    Serial.println("Vault: all accounts saved with AES-GCM encryption.");
    loadVaultAccounts();
  }
  return ok;
}

bool saveDemoAccount() {
  if (!vaultStorageReady) {
    Serial.println("Vault: storage isn't ready.");
    return false;
  }

  if (SD_MMC.exists(VAULT_FILE)) {
    Serial.println("Vault: file already exists; refusing to overwrite it with demo data.");
    return false;
  }

  // Dummy-only data. This is not a real credential.
  const char demo[] = "example.com|demo_user|not-a-real-password";
  bool ok = saveEncryptedPayload((const uint8_t *)demo, strlen(demo));
  if (ok) {
    Serial.println("Vault: dummy account saved encrypted.");
    loadVaultAccount();
  }
  return ok;
}

// =================================================
// TOUCHSCREEN
// =================================================

uint8_t readTouchRegister(uint8_t reg) {
  Wire.beginTransmission(TOUCH_ADDR);
  Wire.write(reg);

  if (Wire.endTransmission(false) != 0) {
    return 0;
  }

  if (Wire.requestFrom(TOUCH_ADDR, (uint8_t)1) != 1) {
    return 0;
  }

  return Wire.read();
}

bool readTouch(uint16_t &x, uint16_t &y) {
  uint8_t count = readTouchRegister(0x02);

  if (count == 0 || count > 2) {
    return false;
  }

  Wire.beginTransmission(TOUCH_ADDR);
  Wire.write(0x03);

  if (Wire.endTransmission(false) != 0) {
    return false;
  }

  if (Wire.requestFrom(TOUCH_ADDR, (uint8_t)4) != 4) {
    return false;
  }

  uint8_t data[4];

  for (int i = 0; i < 4; i++) {
    data[i] = Wire.read();
  }

  uint16_t rawX = ((data[0] & 0x0F) << 8) | data[1];
  uint16_t rawY = ((data[2] & 0x0F) << 8) | data[3];

  // Your confirmed touch-coordinate correction.
  if (rawX > 239 || rawY > 319) {
    return false;
  }

  x = 239 - rawX;
  y = 319 - rawY;

  return true;
}

// =================================================
// DRAWING HELPERS
// =================================================

void drawButton(
  int x, int y, int w, int h,
  const char *label,
  uint16_t fill,
  uint16_t textColour = WHITE
) {
  lcd.fillRoundRect(x, y, w, h, 7, fill);
  lcd.drawRoundRect(x, y, w, h, 7, BORDER);

  lcd.setTextDatum(middle_center);
  lcd.setTextColor(textColour, fill);
  lcd.setTextSize(2);
  lcd.drawString(label, x + w / 2, y + h / 2);
}

void drawBatteryIndicator() {
  // Clear only the battery display area
  lcd.fillRect(174, 3, 64, 34, PANEL);

  // Battery icon dimensions
  const int x = 178;
  const int y = 12;
  const int w = 23;
  const int h = 13;

  uint16_t batteryColour = GREEN;

  if (batteryPercentage <= 20) {
    batteryColour = RED;
  } else if (batteryPercentage <= 40) {
    batteryColour = lcd.color565(255, 180, 50);
  }

  // Battery outline
  lcd.drawRoundRect(x, y, w, h, 2, WHITE);

  // Battery positive terminal
  lcd.fillRect(x + w, y + 4, 3, 5, WHITE);

  // Battery level
  int levelWidth = (w - 4) * batteryPercentage / 100;

  if (levelWidth > 0) {
    lcd.fillRect(
      x + 2,
      y + 2,
      levelWidth,
      h - 4,
      batteryColour
    );
  }

  // Percentage text
  lcd.setTextDatum(middle_left);
  lcd.setTextColor(WHITE, PANEL);
  lcd.setTextSize(1);

  String percentageText = String(batteryPercentage) + "%";
  lcd.drawString(percentageText, 207, 19);
}

/*void drawHeader(const char *title) {
  lcd.fillScreen(BG);
  lcd.fillRect(0, 0, 240, 40, PANEL);

  lcd.setTextDatum(middle_center);
  lcd.setTextColor(CYAN, PANEL);
  lcd.setTextSize(2);
  lcd.drawString(title, 120, 20);

  lcd.drawFastHLine(12, 41, 216, BORDER);
}*/
void drawHeader(const char *title) {
  lcd.fillScreen(BG);
  lcd.fillRect(0, 0, 240, 40, PANEL);

  // Page title on the left
  lcd.setTextDatum(middle_left);
  lcd.setTextColor(CYAN, PANEL);
  lcd.setTextSize(1);
  lcd.drawString(title, 10, 20);

  // Battery indicator on the right
  drawBatteryIndicator();

  lcd.drawFastHLine(12, 41, 216, BORDER);
}

void drawPINStatus() {
  if (statusMessage.length() == 0) return;

  if ((int32_t)(millis() - statusUntil) >= 0) {
    statusMessage = "";
    return;
  }

  lcd.fillRect(10, 99, 220, 17, BG);
  lcd.setTextDatum(middle_center);
  lcd.setTextSize(1);
  lcd.setTextColor(RED, BG);
  lcd.drawString(statusMessage, 120, 107);
}

void setStatus(const char *message, uint32_t duration) {
  statusMessage = message;
  statusUntil = millis() + duration;
}

// =================================================
// FINGERPRINT-FIRST LOCK SCREEN
// =================================================

void drawFingerprintScreen() {
  drawHeader("SECURE VAULT");

  // Simple fingerprint indicator
  lcd.drawCircle(120, 91, 27, CYAN);
  lcd.drawCircle(120, 91, 21, CYAN);
  lcd.drawCircle(120, 91, 14, CYAN);

  lcd.fillRect(115, 104, 10, 17, BG);

  lcd.setTextDatum(middle_center);
  lcd.setTextColor(WHITE, BG);
  lcd.setTextSize(2);

  if (!fingerprintReady) {
    lcd.drawString("Sensor unavailable", 120, 143);
    lcd.setTextColor(RED, BG);
    lcd.setTextSize(1);
    lcd.drawString("Use your PIN to unlock", 120, 165);
  } else if (fingerprintFailures >= MAX_FP_FAILURES) {
    lcd.drawString("PIN required", 120, 143);
    lcd.setTextColor(MUTED, BG);
    lcd.setTextSize(1);
    lcd.drawString("Three failed fingerprint attempts", 120, 165);
  } else {
    lcd.drawString("Fingerprint unlock", 120, 143);
    lcd.setTextColor(MUTED, BG);
    lcd.setTextSize(1);

    if (fingerprintWaitingForRemoval) {
      lcd.drawString("Remove your finger", 120, 165);
    } else {
      lcd.drawString("Place your finger on sensor", 120, 165);
    }

    char attempts[32];
    snprintf(
      attempts, sizeof(attempts),
      "Failed attempts: %u/%u",
      fingerprintFailures, MAX_FP_FAILURES
    );
    lcd.drawString(attempts, 120, 190);
  }

  drawButton(
    20, 224, 200, 36,
    "USE PIN INSTEAD",
    lcd.color565(0, 105, 125),
    WHITE
  );

  if (powerOffConfirm) {
    drawButton(12, 267, 102, 38, "CANCEL", PANEL, WHITE);
    drawButton(126, 267, 102, 38, "YES, OFF", lcd.color565(120, 35, 40), WHITE);
  } else {
    drawButton(20, 267, 200, 38, "POWER OFF", lcd.color565(120, 35, 40), WHITE);
  }

  // Show a recent fingerprint result, if any.
  if (statusMessage.length() > 0 &&
      (int32_t)(millis() - statusUntil) < 0) {
    lcd.fillRect(10, 197, 220, 18, BG);
    lcd.setTextDatum(middle_center);
    lcd.setTextColor(
      fingerprintFailures > 0 ? RED : GREEN, BG
    );
    lcd.setTextSize(1);
    lcd.drawString(statusMessage, 120, 213);
  }
}

// =================================================
// PIN SCREEN
// =================================================

void drawPINDots() {
  for (int i = 0; i < 4; i++) {
    int x = 78 + i * 28;

    lcd.fillCircle(x, 78, 7, PANEL);
    lcd.drawCircle(x, 78, 7, CYAN);

    if (i < (int)enteredPIN.length()) {
      lcd.fillCircle(x, 78, 4, CYAN);
    }
  }
}

void drawPINScreen() {
  drawHeader("SECURE VAULT");

  lcd.setTextDatum(middle_center);
  lcd.setTextColor(WHITE, BG);
  lcd.setTextSize(2);
  lcd.drawString("Enter your PIN", 120, 56);

  drawPINDots();

  const char *keys[4][3] = {
    {"1", "2", "3"},
    {"4", "5", "6"},
    {"7", "8", "9"},
    {"CLR", "0", "<"}
  };

  int xs[3] = {20, 92, 164};
  int ys[4] = {119, 154, 189, 224};

  for (int r = 0; r < 4; r++) {
    for (int c = 0; c < 3; c++) {
      uint16_t fill = PANEL;
      uint16_t text = WHITE;

      if (r == 3 && c == 0) {
        fill = lcd.color565(95, 35, 40);
        text = lcd.color565(255, 205, 205);
      }

      drawButton(
        xs[c], ys[r], 56, 29,
        keys[r][c], fill, text
      );
    }
  }

  drawButton(
    20, 265, 200, 36, "UNLOCK",
    lcd.color565(0, 105, 125), WHITE
  );

  drawPINStatus();
}

void refreshPINScreen() {
  drawPINDots();
  drawPINStatus();
}

void enterDigit(char digit) {
  if (enteredPIN.length() < 4) {
    enteredPIN += digit;
    lastActivity = millis();
    refreshPINScreen();
  }
}

void clearPIN() {
  enteredPIN = "";
  statusMessage = "";
  drawPINScreen();
}

void unlockVault() {
  if (enteredPIN.length() != 4) {
    setStatus("Enter all four digits", 1800);
    refreshPINScreen();
    return;
  }

  if (enteredPIN == DEV_PIN) {
    enteredPIN = "";
    statusMessage = "";

    // A successful PIN unlock resets fingerprint failures.
    fingerprintFailures = 0;
    fingerprintWaitingForRemoval = true;

    currentScreen = HOME_SCREEN;
    lastActivity = millis();

    Serial.println("Vault unlocked with PIN.");
    drawHomeScreen();
  } else {
    enteredPIN = "";
    setStatus("Incorrect PIN", 1800);
    drawPINScreen();
    Serial.println("Incorrect PIN.");
  }
}

// =================================================
// FINGERPRINT PROCESSING
// =================================================

void fingerprintUnlockSuccess() {
  Serial.printf(
    "Fingerprint match: ID %u, confidence %u\n",
    finger.fingerID, finger.confidence
  );

  fingerprintFailures = 0;
  fingerprintWaitingForRemoval = true;
  enteredPIN = "";
  statusMessage = "";

  currentScreen = HOME_SCREEN;
  lastActivity = millis();

  Serial.println("Vault unlocked with fingerprint.");
  drawHomeScreen();
}

void fingerprintAttemptFailed(const char *message) {
  fingerprintFailures++;

  Serial.printf(
    "Fingerprint attempt failed (%u/%u): %s\n",
    fingerprintFailures, MAX_FP_FAILURES, message
  );

  if (fingerprintFailures >= MAX_FP_FAILURES) {
    setStatus("PIN fallback activated", 3000);
    currentScreen = PIN_SCREEN;
    enteredPIN = "";
    drawPINScreen();
  } else {
    setStatus(message, 2000);
    drawFingerprintScreen();
  }
}

// Polls the sensor without an enrolment/search loop.
// A finger must be removed before another attempt.
void pollFingerprint() {
  if (!fingerprintReady) return;
  if (currentScreen != FINGERPRINT_SCREEN) return;

  uint32_t now = millis();

  if (now - lastFingerprintPoll < FP_POLL_MS) return;
  lastFingerprintPoll = now;

  // R307S touch detection is active LOW
if (digitalRead(TOUCH_PIN) == HIGH) {
  // No finger touching the sensor
  fingerprintWaitingForRemoval = false;
  return;
}

// Avoid processing the same finger repeatedly
if (fingerprintWaitingForRemoval) {
  return;
}

  int p = finger.getImage();

  if (p == FINGERPRINT_NOFINGER) {
    fingerprintWaitingForRemoval = false;
    return;
  }

  // Ignore the same finger until it is removed.
  if (fingerprintWaitingForRemoval) return;

  if (p != FINGERPRINT_OK) {
    // Sensor/communication errors aren't treated as
    // a mismatched fingerprint.
    return;
  }

  // Finger image captured. Require removal before
  // accepting another attempt.
  fingerprintWaitingForRemoval = true;

  p = finger.image2Tz();

  if (p != FINGERPRINT_OK) {
    fingerprintAttemptFailed("Could not read fingerprint");
    return;
  }

  p = finger.fingerSearch();

  if (p == FINGERPRINT_OK) {
    fingerprintUnlockSuccess();
  } else if (p == FINGERPRINT_NOTFOUND) {
    fingerprintAttemptFailed("Fingerprint not recognised");
  } else {
    // Unexpected protocol/device errors are logged,
    // but don't count as a wrong-finger attempt.
    Serial.printf("Fingerprint search error: %d\n", p);
    setStatus("Sensor communication error", 2000);
    drawFingerprintScreen();
  }
}

// =================================================
// AOA - ADD OVER AIR (ADD-ONLY WEB INTERFACE)
// =================================================

String aoaPage(const String &body, const String &title) {
  String html;
  html.reserve(body.length() + 1000);
  html += F("<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<meta http-equiv='Cache-Control' content='no-store'><title>");
  html += title;
  html += F("</title><style>body{font-family:Arial,sans-serif;background:#0f1623;color:#f5f8ff;margin:0;padding:22px}main{max-width:420px;margin:auto;background:#233042;padding:20px;border-radius:14px}h2{margin-top:0;color:#46dcf0}label{display:block;margin:14px 0 5px}input{box-sizing:border-box;width:100%;padding:12px;border-radius:7px;border:1px solid #789;background:#101a28;color:white;font-size:16px}button{margin-top:18px;width:100%;padding:13px;border:0;border-radius:8px;background:#087e91;color:white;font-size:16px;font-weight:bold}.note{font-size:13px;color:#b0bed0;line-height:1.45}.ok{color:#5ae696}.err{color:#ff777d}</style></head><body><main>");
  html += F("<h2>ES3C28P Vault</h2><p class='note'>AOA — Add Over Air. This page can add credentials only. It cannot list, view, edit, or delete saved accounts.</p>");
  html += body;
  html += F("</main>");
  // Keep the device from auto-locking while the owner is actively entering data.
  html += F("<script>setInterval(()=>fetch('/ping',{cache:'no-store'}).catch(()=>{}),20000);</script></body></html>");
  return html;
}

bool aoaClientAuthenticated() {
  if (!aoaActive || aoaAuthenticatedIP == IPAddress(0, 0, 0, 0)) return false;
  if ((int32_t)(millis() - aoaSessionUntil) >= 0) {
    aoaAuthenticatedIP = IPAddress(0, 0, 0, 0);
    return false;
  }
  return aoaServer.client().remoteIP() == aoaAuthenticatedIP;
}

bool validAOAField(const String &value, size_t maxLen) {
  if (value.length() == 0 || value.length() > maxLen) return false;
  for (size_t i = 0; i < value.length(); i++) {
    char c = value[i];
    if (c == '|' || c == '\n' || c == '\r' || c == '\0') return false;
  }
  return true;
}

void handleAOARoot() {
  lastActivity = millis();
  if (aoaClientAuthenticated()) {
    String body = F("<p class='ok'>PIN verified. Add a new credential below.</p><form method='POST' action='/add'>");
    body += F("<label>Website / service</label><input name='site' maxlength='40' required autocomplete='off' placeholder='example.com'>");
    body += F("<label>Username</label><input name='user' maxlength='40' required autocomplete='off'>");
    body += F("<label>Password</label><input name='pass' type='password' maxlength='64' required autocomplete='new-password'>");
    body += F("<button type='submit'>Save new credential</button></form><p class='note'>Existing entries are never sent to this browser. The web interface does not provide account viewing or deletion.</p>");
    aoaServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    aoaServer.send(200, "text/html", aoaPage(body));
    return;
  }
  String body = F("<form method='POST' action='/login'><label>Master PIN</label><input name='pin' type='password' inputmode='numeric' maxlength='12' required autocomplete='off'><button type='submit'>Unlock add-only access</button></form><p class='note'>Only adding new credentials is allowed. Saved credentials cannot be viewed or deleted here.</p>");
  aoaServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  aoaServer.send(200, "text/html", aoaPage(body));
}

void handleAOALogin() {
  lastActivity = millis();
  if (!aoaActive) { aoaServer.send(503, "text/plain", "AOA is disabled"); return; }
  if ((int32_t)(millis() - aoaPinLockoutUntil) < 0) {
    aoaServer.send(429, "text/html", aoaPage(F("<p class='err'>Too many incorrect PIN attempts. Wait 30 seconds, then try again.</p><p><a href='/' style='color:#46dcf0'>Back</a></p>")));
    return;
  }
  String pin = aoaServer.arg("pin");
  if (pin.length() > 0 && pin == DEV_PIN) {
    pin = "";
    aoaBadPinAttempts = 0;
    aoaAuthenticatedIP = aoaServer.client().remoteIP();
    aoaSessionUntil = millis() + AOA_SESSION_MS;
    aoaServer.sendHeader("Cache-Control", "no-store");
    aoaServer.sendHeader("Location", "/", true);
    aoaServer.send(303, "text/plain", "PIN accepted. Return to the add-entry page.");
    return;
  }
  pin = "";
  aoaBadPinAttempts++;
  if (aoaBadPinAttempts >= 5) {
    aoaBadPinAttempts = 0;
    aoaPinLockoutUntil = millis() + AOA_LOCKOUT_MS;
  }
  aoaServer.send(401, "text/html", aoaPage(F("<p class='err'>Incorrect PIN.</p><p><a href='/' style='color:#46dcf0'>Try again</a></p>")));
}

void handleAOAAdd() {
  lastActivity = millis();
  if (!aoaClientAuthenticated()) {
    aoaServer.send(401, "text/html", aoaPage(F("<p class='err'>PIN session expired. Please sign in again.</p><p><a href='/'>Sign in</a></p>")));
    return;
  }
  String site = aoaServer.arg("site");
  String user = aoaServer.arg("user");
  String pass = aoaServer.arg("pass");
  if (!validAOAField(site, 40) || !validAOAField(user, 40) || !validAOAField(pass, 64)) {
    site = ""; user = ""; pass = "";
    aoaServer.send(400, "text/html", aoaPage(F("<p class='err'>Invalid or too-long field. No entry was saved.</p><p><a href='/'>Back to form</a></p>")));
    return;
  }
  if (!vaultStorageReady) {
    site = ""; user = ""; pass = "";
    aoaServer.send(503, "text/html", aoaPage(F("<p class='err'>Encrypted storage is unavailable. Nothing was saved.</p>")));
    return;
  }
  bool loaded = loadVaultAccounts();
  if (!loaded && (vaultFileInvalid || SD_MMC.exists(VAULT_FILE))) {
    site = ""; user = ""; pass = "";
    aoaServer.send(500, "text/html", aoaPage(F("<p class='err'>Vault file could not be validated. Existing data was preserved; nothing was saved.</p>")));
    return;
  }
  if (!SD_MMC.exists(VAULT_FILE)) vaultAccountCount = 0;
  if (vaultAccountCount >= MAX_ACCOUNTS) {
    site = ""; user = ""; pass = "";
    aoaServer.send(409, "text/html", aoaPage(F("<p class='err'>Account capacity reached. No entry was saved.</p><p>Use the device touchscreen to manage existing entries.</p>")));
    return;
  }
  vaultAccounts[vaultAccountCount].site = site;
  vaultAccounts[vaultAccountCount].user = user;
  vaultAccounts[vaultAccountCount].password = pass;
  vaultAccountCount++;
  bool saved = saveAllAccounts();
  site = ""; user = ""; pass = "";
  if (!saved) {
    if (vaultAccountCount) vaultAccountCount--;
    vaultAccounts[vaultAccountCount].site = "";
    vaultAccounts[vaultAccountCount].user = "";
    vaultAccounts[vaultAccountCount].password = "";
    aoaServer.send(500, "text/html", aoaPage(F("<p class='err'>Save failed. The previous vault was retained.</p><p><a href='/'>Return</a></p>")));
    return;
  }
  aoaSessionUntil = millis() + AOA_SESSION_MS;
  aoaServer.sendHeader("Cache-Control", "no-store");
  aoaServer.send(200, "text/html", aoaPage(F("<p class='ok'>New credential saved and encrypted.</p><p>No existing account details were accessed or displayed.</p><p><a href='/' style='color:#46dcf0'>Add another entry</a></p>")));
}

void handleAOAPing() {
  if (aoaClientAuthenticated()) {
    // Heartbeat keeps the physical vault from auto-locking during active entry,
    // but does not extend the web PIN session indefinitely.
    lastActivity = millis();
    aoaServer.sendHeader("Cache-Control", "no-store");
    aoaServer.send(204, "text/plain", "");
  } else {
    aoaServer.send(401, "text/plain", "Session expired");
  }
}

void handleAOANotFound() {
  // Deliberately no API route exists to read, enumerate, edit, or delete saved accounts.
  aoaServer.send(404, "text/plain", "Not found. AOA supports adding new entries only.");
}

void startAOA() {
  if (aoaActive) {
    setStatus("AOA hotspot already active", 1800);
    drawHomeScreen();
    return;
  }
  if (!vaultStorageReady) {
    setStatus("Vault storage unavailable", 2200);
    drawHomeScreen();
    return;
  }
  bool loaded = loadVaultAccounts();
  if (!loaded && (vaultFileInvalid || SD_MMC.exists(VAULT_FILE))) {
    setStatus("Vault storage unavailable", 2200);
    drawHomeScreen();
    return;
  }
  if (!SD_MMC.exists(VAULT_FILE)) vaultAccountCount = 0;
  WiFi.mode(WIFI_AP);
  WiFi.setSleep(false);
  if (!WiFi.softAP(AOA_SSID, AOA_AP_PASSWORD, 6, false, 2)) {
    WiFi.mode(WIFI_OFF);
    setStatus("AOA hotspot failed", 2200);
    Serial.println("AOA: failed to start Wi-Fi access point.");
    drawHomeScreen();
    return;
  }
  aoaAuthenticatedIP = IPAddress(0, 0, 0, 0);
  aoaSessionUntil = 0;
  aoaBadPinAttempts = 0;
  aoaPinLockoutUntil = 0;
  aoaServer.begin();
  aoaActive = true;
  lastActivity = millis();
  Serial.println("AOA hotspot started. Add-only web interface enabled.");
  Serial.printf("AOA SSID: %s\n", AOA_SSID);
  Serial.printf("AOA password: %s\n", AOA_AP_PASSWORD);
  Serial.printf("AOA URL: http://%s/\n", WiFi.softAPIP().toString().c_str());
  // Show the Wi-Fi QR immediately so the phone can join without typing the passphrase.
  currentScreen = AOA_QR_SCREEN;
  drawAOAQRScreen();
  setStatus("Scan QR to join AOA Wi-Fi", 3500);
}

void stopAOA() {
  if (!aoaActive) return;
  aoaServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  aoaActive = false;
  aoaAuthenticatedIP = IPAddress(0, 0, 0, 0);
  aoaSessionUntil = 0;
  aoaBadPinAttempts = 0;
  aoaPinLockoutUntil = 0;
  Serial.println("AOA hotspot stopped; web session cleared.");
}

void serviceAOA() {
  if (aoaActive) aoaServer.handleClient();
}

// =================================================
// AOA WI-FI QR SCREEN
// QR payload follows the standard Wi-Fi QR format. Scanning it lets a phone
// offer to join the WPA2 hotspot without manually typing the password.
// =================================================

void drawAOAQRScreen() {
  drawHeader("AOA WI-FI CONNECT");
  lcd.setTextDatum(middle_center);
  lcd.setTextColor(WHITE, BG);
  lcd.setTextSize(1);
  lcd.drawString("Scan this QR with your phone camera", 120, 52);

  String wifiQR = String("WIFI:T:WPA;S:") + AOA_SSID + ";P:" + AOA_AP_PASSWORD + ";;";
  QRCode qr;
  uint8_t qrBuffer[200];
  qrcode_initText(&qr, qrBuffer, 4, ECC_LOW, wifiQR.c_str());

  // Version 4 is 33 x 33 modules. Four-module quiet zone on each side.
  const int moduleSize = 4;
  const int quiet = 4 * moduleSize;
  const int qrPixels = qr.size * moduleSize;
  const int totalPixels = qrPixels + 2 * quiet;
  const int left = (240 - totalPixels) / 2;
  const int top = 61;
  lcd.fillRect(left, top, totalPixels, totalPixels, WHITE);
  for (uint8_t yy = 0; yy < qr.size; yy++) {
    for (uint8_t xx = 0; xx < qr.size; xx++) {
      if (qrcode_getModule(&qr, xx, yy)) {
        lcd.fillRect(left + quiet + xx * moduleSize,
                     top + quiet + yy * moduleSize,
                     moduleSize, moduleSize, BG);
      }
    }
  }

  lcd.setTextColor(CYAN, BG);
  lcd.setTextSize(1);
  lcd.drawString("ES3C28P-AOA", 120, 236);
  lcd.setTextColor(MUTED, BG);
  lcd.drawString("Then open http://192.168.4.1", 120, 252);
  drawButton(12, 274, 102, 36, "BACK", PANEL);
  drawButton(126, 274, 102, 36, "STOP AOA", lcd.color565(120, 35, 40));
}

void handleAOAQRScreenTouch(uint16_t x, uint16_t y) {
  if (y >= 270 && y <= 315 && x >= 126) {
    stopAOA();
    currentScreen = HOME_SCREEN;
    setStatus("AOA hotspot stopped", 1800);
    drawHomeScreen();
    return;
  }
  if (y >= 270 && y <= 315 && x <= 114) {
    currentScreen = HOME_SCREEN;
    lastActivity = millis();
    drawHomeScreen();
    return;
  }
}

// =================================================
// TEMPORARY HOME SCREEN
// =================================================

void drawHomeScreen() {
  drawHeader("VAULT HOME");
  lcd.setTextDatum(middle_center);
  lcd.setTextColor(GREEN, BG);
  lcd.setTextSize(2);
  lcd.drawString("Unlocked", 120, 77);
  lcd.setTextColor(MUTED, BG);
  lcd.setTextSize(1);
  lcd.drawString("Touchscreen + serial-assisted entry", 120, 102);
  drawButton(20, 116, 200, 36, "My Accounts", PANEL);
  drawButton(20, 160, 200, 36, "Add Account", PANEL);
  drawButton(20, 204, 200, 36, "Generate Password", lcd.color565(0, 105, 125));
  lcd.fillRoundRect(12, 236, 102, 42, 7, lcd.color565(120, 35, 40));
  lcd.drawRoundRect(12, 236, 102, 42, 7, BORDER);
  lcd.setTextDatum(middle_center);
  lcd.setTextColor(WHITE, lcd.color565(120, 35, 40));
  lcd.setTextSize(1);
  lcd.drawString("LOCK VAULT", 63, 257);
  lcd.fillRoundRect(126, 236, 102, 42, 7, aoaActive ? lcd.color565(110, 70, 20) : lcd.color565(0, 105, 125));
  lcd.drawRoundRect(126, 236, 102, 42, 7, BORDER);
  lcd.setTextDatum(middle_center);
  lcd.setTextColor(WHITE, aoaActive ? lcd.color565(110, 70, 20) : lcd.color565(0, 105, 125));
  lcd.setTextSize(1);
  lcd.drawString(aoaActive ? "AOA SHOW QR" : "AOA ADD OVER AIR", 177, 257);
  lcd.setTextColor(MUTED, BG);
  lcd.setTextSize(1);
  if (aoaActive) {
    lcd.drawString("AOA hotspot active", 120, 289);
    lcd.drawString("Tap AOA SHOW QR to reconnect", 120, 305);
  } else {
    lcd.drawString(vaultStorageReady ? "Encrypted storage ready" : "Storage unavailable", 120, 296);
  }
}


static void secureClearGeneratedPassword() {
  volatile char *p = generatedPassword;
  for (size_t i = 0; i < sizeof(generatedPassword); ++i) p[i] = 0;
  generatedPasswordReady = false;
}
static uint32_t secureRandomBelow(uint32_t upperExclusive) {
  const uint32_t threshold = (uint32_t)(-upperExclusive) % upperExclusive;
  uint32_t value;
  do { value = esp_random(); } while (value < threshold);
  return value % upperExclusive;
}
static void generateSecurePassword() {
  static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*_-";
  const uint32_t alphabetLength = sizeof(alphabet) - 1;
  secureClearGeneratedPassword();
  for (size_t i = 0; i < 10; ++i) generatedPassword[i] = alphabet[secureRandomBelow(alphabetLength)];
  generatedPassword[10] = 0;
  generatedPasswordReady = true;
}
static void openGeneratedPasswordSaveForm() {
  if (!generatedPasswordReady) { setStatus("Generate a password first", 1800); drawGenerateScreen(); return; }
  editSite = ""; editUser = ""; editPassword = String(generatedPassword);
  editField = 0; editingExistingAccount = false; passwordVisible = false;
  keyboardShift = false; keyboardSymbols = false;
  currentScreen = ADD_ACCOUNT_SCREEN; lastActivity = millis(); drawAddAccountScreen();
}
void drawGenerateScreen() {
  drawHeader("GENERATE PASSWORD");
  lcd.setTextDatum(middle_center); lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
  lcd.drawString("Secure random password (10 characters)", 120, 65);
  lcd.fillRoundRect(10, 88, 220, 44, 6, PANEL); lcd.drawRoundRect(10, 88, 220, 44, 6, BORDER);
  lcd.setTextColor(WHITE, PANEL); lcd.setTextSize(2);
  lcd.drawString(generatedPasswordReady ? String(generatedPassword) : String("----------"), 120, 110);
  lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
  lcd.drawString("Focus the password field on your phone", 120, 153);
  drawButton(12, 177, 102, 38, "PASS (BLE)", lcd.color565(0, 105, 125));
  drawButton(126, 177, 102, 38, "SAVE", lcd.color565(0, 105, 70));
  drawButton(12, 226, 102, 36, "REGENERATE", PANEL);
  drawButton(126, 226, 102, 36, "CANCEL", lcd.color565(120, 35, 40));
  lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
  lcd.drawString("PASS types it, then opens the save form", 120, 286);
}
void handleGenerateTouch(uint16_t x, uint16_t y) {
  if (y >= 177 && y <= 215) {
    if (x >= 12 && x <= 114) {
      if (!generatedPasswordReady) { setStatus("No password generated", 1800); drawGenerateScreen(); return; }
      if (!bleKeyboardStarted || !bleKeyboard.isConnected()) { setStatus("Pair and connect phone by BLE", 2200); drawGenerateScreen(); return; }
      bleKeyboard.print(String(generatedPassword));
      lastActivity = millis(); openGeneratedPasswordSaveForm(); return;
    }
    if (x >= 126 && x <= 228) { openGeneratedPasswordSaveForm(); return; }
  }
  if (y >= 226 && y <= 264) {
    if (x >= 12 && x <= 114) { generateSecurePassword(); lastActivity = millis(); drawGenerateScreen(); return; }
    if (x >= 126 && x <= 228) { secureClearGeneratedPassword(); currentScreen = HOME_SCREEN; lastActivity = millis(); drawHomeScreen(); return; }
  }
}

void drawAccountsScreen() {
  drawHeader("MY ACCOUNTS");
  if (!vaultStorageReady) {
    lcd.setTextDatum(middle_center); lcd.setTextColor(RED, BG); lcd.setTextSize(1);
    lcd.drawString("microSD storage unavailable", 120, 110);
  } else if (!loadVaultAccounts()) {
    lcd.setTextDatum(middle_center); lcd.setTextSize(1);
    lcd.setTextColor(vaultFileInvalid ? RED : MUTED, BG);
    lcd.drawString(vaultFileInvalid ? "Stored file invalid - preserved" : "No accounts saved yet", 120, 100);
    lcd.setTextColor(MUTED, BG);
    lcd.drawString("Tap Add Account from home", 120, 122);
  } else {
    lcd.setTextDatum(middle_left);
    lcd.setTextSize(1);
    lcd.setTextColor(MUTED, BG);
    lcd.drawString("Select an account", 14, 53);
    for (uint8_t i = 0; i < vaultAccountCount && i < MAX_ACCOUNTS; i++) {
      int y = 60 + i * 26;
      lcd.fillRoundRect(12, y, 216, 23, 5, PANEL);
      lcd.drawRoundRect(12, y, 216, 23, 5, BORDER);
      lcd.setTextColor(WHITE, PANEL);
      lcd.setTextDatum(middle_left);
      String label = String(i + 1) + ". " + vaultAccounts[i].site;
      if (label.length() > 25) label = label.substring(0, 24) + "…";
      lcd.drawString(label, 20, y + 12);
    }
  }
  drawButton(12, 278, 102, 32, "BACK", PANEL);
  drawButton(126, 278, 102, 32, "ADD NEW", lcd.color565(0, 105, 125));
}

void drawAccountDetailScreen() {
  drawHeader("ACCOUNT DETAILS");
  if (selectedAccount < 0 || selectedAccount >= vaultAccountCount) {
    lcd.setTextDatum(middle_center); lcd.setTextColor(RED, BG); lcd.setTextSize(1);
    lcd.drawString("No account selected", 120, 110);
  } else {
    VaultAccount &a = vaultAccounts[selectedAccount];
    lcd.setTextDatum(middle_center);
    lcd.setTextColor(CYAN, BG); lcd.setTextSize(2);
    String site = a.site;
    if (site.length() > 18) site = site.substring(0, 17) + "…";
    lcd.drawString(site, 120, 58);

    // Keep credential text in a fixed left-aligned area. The P buttons sit
    // separately at the right and cannot push or clip the first characters.
    lcd.setTextDatum(middle_left);
    lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
    lcd.drawString("USERNAME", 12, 91);
    lcd.setTextColor(WHITE, BG); lcd.setTextSize(1);
    String user = a.user;
    while (user.length() > 0 && lcd.textWidth(user) > 168) user.remove(user.length() - 1);
    lcd.fillRect(10, 96, 174, 22, BG);
    lcd.drawString(user, 12, 106);

    lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
    lcd.drawString(passwordVisible ? "PASSWORD (VISIBLE)" : "PASSWORD (HIDDEN)", 12, 130);
    lcd.setTextColor(WHITE, BG); lcd.setTextSize(1);
    String pass = passwordVisible ? a.password : String("****************");
    while (pass.length() > 0 && lcd.textWidth(pass) > 168) pass.remove(pass.length() - 1);
    lcd.fillRect(10, 140, 174, 22, BG);
    lcd.drawString(pass, 12, 150);

    drawButton(190, 85, 38, 29, "P", PANEL);
    drawButton(190, 129, 38, 29, "P", PANEL);
    drawButton(12, 165, 102, 31, passwordVisible ? "HIDE PASS" : "SHOW PASS", PANEL);
    drawButton(126, 165, 102, 31, "EDIT", PANEL);
    drawButton(12, 207, 216, 31, "DELETE ACCOUNT", lcd.color565(120, 35, 40), WHITE);
    lcd.setTextDatum(middle_center); lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
    lcd.drawString("Focus a field on your phone, then tap P", 120, 250);
  }
  drawButton(20, 272, 200, 35, "BACK TO LIST", PANEL);
}

void pasteCredentialOverBLE(const String &credential, const char *label) {
  if (currentScreen != ACCOUNT_DETAIL_SCREEN ||
      selectedAccount < 0 || selectedAccount >= vaultAccountCount) return;
  if (!bleKeyboardStarted || !bleKeyboard.isConnected()) {
    setStatus("Pair BLE keyboard first", 2200);
    Serial.println("BLE paste unavailable: keyboard is not connected.");
    drawAccountDetailScreen();
    return;
  }
  if (credential.length() == 0) {
    setStatus("Credential is empty", 1800);
    drawAccountDetailScreen();
    return;
  }
  bleKeyboard.print(credential);
  lastActivity = millis();
  Serial.printf("BLE HID: sent %s to the focused field.\n", label);
  setStatus("Credential sent over BLE", 1500);
  drawAccountDetailScreen();
}

void drawDeleteConfirmScreen() {
  drawHeader("DELETE ACCOUNT?");
  lcd.setTextDatum(middle_center); lcd.setTextColor(WHITE, BG); lcd.setTextSize(1);
  if (selectedAccount >= 0 && selectedAccount < vaultAccountCount) {
    String site = vaultAccounts[selectedAccount].site;
    if (site.length() > 25) site = site.substring(0, 24) + "…";
    lcd.drawString("Delete: " + site + "?", 120, 105);
    lcd.setTextColor(RED, BG);
    lcd.drawString("This cannot be undone.", 120, 132);
    lcd.setTextColor(MUTED, BG);
    lcd.drawString("Keep at least one account in this stage.", 120, 157);
  }
  drawButton(12, 205, 102, 42, "CANCEL", PANEL);
  drawButton(126, 205, 102, 42, "DELETE", lcd.color565(140, 25, 35), WHITE);
}

static void drawKey(int x, int y, int w, int h, const String &label) {
  lcd.fillRoundRect(x, y, w, h, 3, PANEL);
  lcd.drawRoundRect(x, y, w, h, 3, BORDER);
  lcd.setTextDatum(middle_center); lcd.setTextColor(WHITE, PANEL); lcd.setTextSize(1);
  lcd.drawString(label, x + w/2, y + h/2);
}

void drawAddAccountScreen() {
  drawHeader(editingExistingAccount ? "EDIT ACCOUNT" : "ADD ACCOUNT");
  String fields[3] = {editSite, editUser, editPassword};
  const char *names[3] = {"SITE", "USER", "PASS"};
  for (int i = 0; i < 3; i++) {
    int y = 48 + i * 25;
    uint16_t fill = (editField == i) ? lcd.color565(0, 75, 90) : PANEL;
    lcd.fillRoundRect(6, y, 228, 22, 4, fill);
    lcd.drawRoundRect(6, y, 228, 22, 4, (editField == i) ? CYAN : BORDER);
    lcd.setTextDatum(middle_left); lcd.setTextSize(1); lcd.setTextColor(CYAN, fill);
    lcd.drawString(names[i], 12, y + 11);
    lcd.setTextColor(WHITE, fill);
    String value = fields[i];
    if (i == 2 && value.length()) { String masked = ""; for (size_t j = 0; j < value.length(); j++) masked += '*'; value = masked; }
    if (value.length() > 23) value = value.substring(value.length() - 23);
    lcd.drawString(value, 53, y + 11);
  }
  const char *rowsLetters[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
  const char *rowsSymbols[3] = {"1234567890", "@#$%&*-_+", "./:!?()"};
  for (int r = 0; r < 3; r++) {
    String row = keyboardSymbols ? String(rowsSymbols[r]) : String(rowsLetters[r]);
    int keyW = (r == 0) ? 22 : (r == 1 ? 23 : 25);
    int gap = 1;
    int total = row.length() * keyW + (row.length() - 1) * gap;
    int x = (240 - total) / 2;
    if (r == 1) x = 14;
    if (r == 2) x = 25;
    for (int k = 0; k < row.length(); k++) {
      char ch = row[k];
      if (!keyboardSymbols && keyboardShift && ch >= 'a' && ch <= 'z') ch -= 32;
      drawKey(x + k * (keyW + gap), 128 + r * 29, keyW, 25, String(ch));
    }
  }
  drawKey(5, 218, 42, 24, keyboardSymbols ? "ABC" : "123");
  drawKey(50, 218, 42, 24, "SHIFT");
  drawKey(95, 218, 42, 24, "DEL");
  drawKey(140, 218, 95, 24, "SPACE");
  drawButton(5, 251, 74, 30, "NEXT", PANEL);
  drawButton(83, 251, 74, 30, "SAVE", lcd.color565(0, 105, 70));
  drawButton(161, 251, 74, 30, "CANCEL", lcd.color565(120, 35, 40));
  lcd.setTextDatum(middle_center); lcd.setTextColor(MUTED, BG); lcd.setTextSize(1);
  lcd.drawString("Optional desktop entry: Serial Monitor", 120, 297);
}

void enterVaultDeepSleep() {
  // Stop network services and clear active session state before sleeping.
  stopAOA();
  aoaServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);

  enteredPIN = "";
  statusMessage = "";
  accountSite = "";
  accountUser = "";
  accountPassword = "";
  editSite = "";
  editUser = "";
  editPassword = "";
  serialLineBuffer = "";
  for (uint8_t i = 0; i < MAX_ACCOUNTS; i++) {
    vaultAccounts[i].site = "";
    vaultAccounts[i].user = "";
    vaultAccounts[i].password = "";
  }
  vaultAccountCount = 0;
  accountLoaded = false;
  secureClearGeneratedPassword();
  memset(vaultKey, 0, sizeof(vaultKey));
  powerOffConfirm = false;

  // Close peripherals where supported. Deep sleep itself powers down the
  // ESP32-S3 digital peripherals and radio; RESET is the intended restart.
  FingerSerial.end();
  SD_MMC.end();
  digitalWrite(TFT_BL, LOW);
  delay(100);

  Serial.println("Vault entering deep sleep. Press RESET to restart.");
  Serial.flush();
  esp_deep_sleep_start();
}

void lockVault() {
  stopAOA();
  enteredPIN = "";
  statusMessage = "";
  // Clear credential copies and unsaved form data from RAM when locking.
  accountSite = ""; accountUser = ""; accountPassword = "";
  for (uint8_t i = 0; i < MAX_ACCOUNTS; i++) {
    vaultAccounts[i].site = "";
    vaultAccounts[i].user = "";
    vaultAccounts[i].password = "";
  }
  vaultAccountCount = 0;
  accountLoaded = false;
  editSite = ""; editUser = ""; editPassword = "";
  secureClearGeneratedPassword();
  editingExistingAccount = false; passwordVisible = false;

  // This is a new lock session following a successful
  // unlock; start its fingerprint failure count at zero.
  fingerprintFailures = 0;
  fingerprintWaitingForRemoval = true;

  currentScreen = FINGERPRINT_SCREEN;
  powerOffConfirm = false;
  lastActivity = millis();

  Serial.println("Vault locked.");
  drawFingerprintScreen();
}

// =================================================
// TOUCH HANDLING
// =================================================

void handleFingerprintTouch(uint16_t x, uint16_t y) {
  // PIN fallback remains available above the power control.
  if (x >= 20 && x <= 220 && y >= 224 && y <= 260) {
    powerOffConfirm = false;
    enteredPIN = "";
    statusMessage = "";
    currentScreen = PIN_SCREEN;
    drawPINScreen();
    Serial.println("PIN fallback selected.");
    return;
  }

  if (y >= 267 && y <= 305) {
    if (!powerOffConfirm) {
      powerOffConfirm = true;
      statusMessage = "";
      drawFingerprintScreen();
      Serial.println("Power off requested; awaiting confirmation.");
      return;
    }

    if (x >= 126 && x <= 228) {
      Serial.println("Power off confirmed.");
      enterVaultDeepSleep();
      return;
    }

    if (x >= 12 && x <= 114) {
      powerOffConfirm = false;
      drawFingerprintScreen();
      Serial.println("Power off cancelled.");
      return;
    }
  }
}

void handlePINTouch(uint16_t x, uint16_t y) {
  int col = -1;

  if (x >= 20 && x <= 76) col = 0;
  else if (x >= 92 && x <= 148) col = 1;
  else if (x >= 164 && x <= 220) col = 2;

  if (col >= 0) {
    int row = -1;

    if (y >= 119 && y <= 148) row = 0;
    else if (y >= 154 && y <= 183) row = 1;
    else if (y >= 189 && y <= 218) row = 2;
    else if (y >= 224 && y <= 253) row = 3;

    if (row >= 0) {
      if (row < 3) {
        const char digits[3][3] = {
          {'1', '2', '3'},
          {'4', '5', '6'},
          {'7', '8', '9'}
        };

        enterDigit(digits[row][col]);
      } else if (col == 0) {
        clearPIN();
      } else if (col == 1) {
        enterDigit('0');
      } else {
        if (enteredPIN.length() > 0) {
          enteredPIN.remove(enteredPIN.length() - 1);
        }

        lastActivity = millis();
        refreshPINScreen();
      }

      return;
    }
  }

  if (x >= 20 && x <= 220 &&
      y >= 265 && y <= 301) {
    unlockVault();
  }
}

void handleHomeTouch(uint16_t x, uint16_t y) {
  if (y >= 236 && y <= 278 && x >= 12 && x <= 114) { lockVault(); return; }
  if (y >= 236 && y <= 278 && x >= 126 && x <= 228) {
    if (aoaActive) {
      currentScreen = AOA_QR_SCREEN;
      drawAOAQRScreen();
    } else {
      startAOA();
    }
    lastActivity = millis();
    return;
  }
  if (x >= 20 && x <= 220 && y >= 116 && y <= 152) {
    currentScreen = MY_ACCOUNTS_SCREEN; lastActivity = millis(); drawAccountsScreen(); return;
  }
  if (x >= 20 && x <= 220 && y >= 160 && y <= 196) {
    if (!vaultStorageReady) { setStatus("Storage unavailable", 2000); drawHomeScreen(); return; }
    if (!loadVaultAccounts() && vaultFileInvalid) {
      Serial.println("Add Account: existing file invalid; preserved.");
      setStatus("Invalid vault file - preserved", 2500); drawHomeScreen(); return;
    }
    if (!accountLoaded && !SD_MMC.exists(VAULT_FILE)) vaultAccountCount = 0;
    if (vaultAccountCount >= MAX_ACCOUNTS) { setStatus("Account limit reached", 2200); drawHomeScreen(); return; }
    editSite = ""; editUser = ""; editPassword = ""; editField = 0;
    editingExistingAccount = false; passwordVisible = false;
    keyboardShift = false; keyboardSymbols = false;
    currentScreen = ADD_ACCOUNT_SCREEN; lastActivity = millis(); drawAddAccountScreen();
    Serial.println("Add Account: editor opened. Optional serial entry: SITE=value / USER=value / PASS=value, one command per line.");
    return;
  }
  if (x >= 20 && x <= 220 && y >= 204 && y <= 240) {
    if (!vaultStorageReady) { setStatus("Storage unavailable", 2000); drawHomeScreen(); return; }
    if (!loadVaultAccounts() && vaultFileInvalid) { setStatus("Invalid vault file - preserved", 2500); drawHomeScreen(); return; }
    if (!SD_MMC.exists(VAULT_FILE)) vaultAccountCount = 0;
    if (vaultAccountCount >= MAX_ACCOUNTS) { setStatus("Account limit reached", 2200); drawHomeScreen(); return; }
    generateSecurePassword();
    currentScreen = GENERATE_SCREEN; lastActivity = millis(); drawGenerateScreen();
    return;
  }
}

void handleAccountsTouch(uint16_t x, uint16_t y) {
  if (y >= 278 && y <= 312) {
    if (x < 120) { currentScreen = HOME_SCREEN; drawHomeScreen(); }
    else { editSite = ""; editUser = ""; editPassword = ""; editField = 0; editingExistingAccount = false; keyboardShift = false; keyboardSymbols = false; currentScreen = ADD_ACCOUNT_SCREEN; drawAddAccountScreen(); }
    lastActivity = millis(); return;
  }
  if (x >= 12 && x <= 228 && y >= 60 && y < 268) {
    int idx = (y - 60) / 26;
    if (idx >= 0 && idx < vaultAccountCount && idx < MAX_ACCOUNTS) {
      selectedAccount = idx;
      passwordVisible = false;
      currentScreen = ACCOUNT_DETAIL_SCREEN;
      lastActivity = millis();
      drawAccountDetailScreen();
    }
  }
}

void handleAccountDetailTouch(uint16_t x, uint16_t y) {
  if (y >= 272 && y <= 310) {
    passwordVisible = false;
    currentScreen = MY_ACCOUNTS_SCREEN; lastActivity = millis(); drawAccountsScreen(); return;
  }
  if (selectedAccount < 0 || selectedAccount >= vaultAccountCount) return;

  // BLE HID paste buttons: tap P after focusing the target field on the phone.
  if (x >= 190 && x <= 228 && y >= 85 && y <= 114) {
    pasteCredentialOverBLE(vaultAccounts[selectedAccount].user, "username");
    return;
  }
  if (x >= 190 && x <= 228 && y >= 129 && y <= 158) {
    pasteCredentialOverBLE(vaultAccounts[selectedAccount].password, "password");
    return;
  }

  if (y >= 165 && y <= 198) {
    if (x < 120) passwordVisible = !passwordVisible;
    else {
      editSite = vaultAccounts[selectedAccount].site;
      editUser = vaultAccounts[selectedAccount].user;
      editPassword = vaultAccounts[selectedAccount].password;
      editField = 0; keyboardShift = false; keyboardSymbols = false;
      editingExistingAccount = true;
      currentScreen = ADD_ACCOUNT_SCREEN;
      drawAddAccountScreen();
      Serial.println("Edit Account: editor opened; save replaces the selected record.");
      return;
    }
    lastActivity = millis(); drawAccountDetailScreen(); return;
  }
  if (y >= 207 && y <= 240) {
    currentScreen = DELETE_CONFIRM_SCREEN; lastActivity = millis(); drawDeleteConfirmScreen(); return;
  }
}

void handleDeleteConfirmTouch(uint16_t x, uint16_t y) {
  if (y < 205 || y > 250) return;
  if (x < 120) {
    currentScreen = ACCOUNT_DETAIL_SCREEN; lastActivity = millis(); drawAccountDetailScreen(); return;
  }
  if (selectedAccount < 0 || selectedAccount >= vaultAccountCount) {
    currentScreen = MY_ACCOUNTS_SCREEN; drawAccountsScreen(); return;
  }
  if (vaultAccountCount <= 1) {
    setStatus("Keep one account; delete unavailable", 2500);
    currentScreen = ACCOUNT_DETAIL_SCREEN; drawAccountDetailScreen(); return;
  }
  VaultAccount removed = vaultAccounts[selectedAccount];
  for (uint8_t i = selectedAccount; i + 1 < vaultAccountCount; i++) {
    vaultAccounts[i] = vaultAccounts[i + 1];
  }
  vaultAccounts[vaultAccountCount - 1].site = "";
  vaultAccounts[vaultAccountCount - 1].user = "";
  vaultAccounts[vaultAccountCount - 1].password = "";
  vaultAccountCount--;
  if (selectedAccount >= vaultAccountCount) selectedAccount = vaultAccountCount - 1;
  if (saveAllAccounts()) {
    removed.site = ""; removed.user = ""; removed.password = "";
    passwordVisible = false;
    Serial.println("Delete Account: selected record removed and vault saved.");
    setStatus("Account deleted", 1800);
    currentScreen = MY_ACCOUNTS_SCREEN; drawAccountsScreen();
  } else {
    // Restore the removed record and original ordering if persistence failed.
    for (int i = vaultAccountCount; i > selectedAccount; i--) vaultAccounts[i] = vaultAccounts[i - 1];
    vaultAccounts[selectedAccount] = removed;
    vaultAccountCount++;
    setStatus("Delete failed; account restored", 2500);
    currentScreen = ACCOUNT_DETAIL_SCREEN; drawAccountDetailScreen();
  }
}

void handleAddAccountTouch(uint16_t x, uint16_t y) {
  // Select one of the three input fields.
  if (y >= 48 && y < 123 && x >= 6 && x <= 234) {
    editField = (y - 48) / 25;
    if (editField > 2) editField = 2;
    drawAddAccountScreen(); return;
  }
  // On-screen keyboard: 3 rows of characters.
  if (y >= 128 && y < 211) {
    int row = (y - 128) / 29;
    const char *rowsLetters[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
    const char *rowsSymbols[3] = {"1234567890", "@#$%&*-_+", "./:!?()"};
    String rowText = keyboardSymbols ? String(rowsSymbols[row]) : String(rowsLetters[row]);
    int keyW = row == 0 ? 22 : (row == 1 ? 23 : 25);
    int gap = 1;
    int total = rowText.length() * keyW + (rowText.length() - 1) * gap;
    int startX = (240 - total) / 2;
    if (row == 1) startX = 14;
    if (row == 2) startX = 25;
    int idx = (x - startX) / (keyW + gap);
    if (idx >= 0 && idx < rowText.length() && x >= startX && x <= startX + total) {
      char ch = rowText[idx];
      if (!keyboardSymbols && keyboardShift && ch >= 'a' && ch <= 'z') ch -= 32;
      String *target = editField == 0 ? &editSite : (editField == 1 ? &editUser : &editPassword);
      int maxLen = editField == 0 ? 40 : (editField == 1 ? 40 : 64);
      if (target->length() < maxLen) *target += ch;
      lastActivity = millis(); drawAddAccountScreen(); return;
    }
  }
  if (y >= 218 && y <= 242) {
    if (x < 48) keyboardSymbols = !keyboardSymbols;
    else if (x < 93) keyboardShift = !keyboardShift;
    else if (x < 138) {
      String *target = editField == 0 ? &editSite : (editField == 1 ? &editUser : &editPassword);
      if (target->length()) target->remove(target->length() - 1);
    } else {
      String *target = editField == 0 ? &editSite : (editField == 1 ? &editUser : &editPassword);
      int maxLen = editField == 0 ? 40 : (editField == 1 ? 40 : 64);
      if (target->length() < maxLen) *target += ' ';
    }
    lastActivity = millis(); drawAddAccountScreen(); return;
  }
  if (y >= 251 && y <= 284) {
    if (x < 80) { editField = (editField + 1) % 3; drawAddAccountScreen(); return; }
    if (x < 160) {
      if (!editSite.length() || !editUser.length() || !editPassword.length()) {
        setStatus("Fill site, username, password", 2200); drawAddAccountScreen(); return;
      }
      if (!loadVaultAccounts() && vaultFileInvalid) {
        setStatus("Vault file invalid - preserved", 2500); drawAddAccountScreen(); return;
      }
      if (!SD_MMC.exists(VAULT_FILE)) vaultAccountCount = 0;
      if (editingExistingAccount) {
        if (selectedAccount < 0 || selectedAccount >= vaultAccountCount) {
          setStatus("Selected account unavailable", 2200); drawAddAccountScreen(); return;
        }
        VaultAccount old = vaultAccounts[selectedAccount];
        vaultAccounts[selectedAccount].site = editSite;
        vaultAccounts[selectedAccount].user = editUser;
        vaultAccounts[selectedAccount].password = editPassword;
        if (saveAllAccounts()) {
          old.site = ""; old.user = ""; old.password = "";
          editSite = ""; editUser = ""; editPassword = ""; editingExistingAccount = false; passwordVisible = false;
          Serial.println("Edit Account: updated credential saved encrypted.");
          currentScreen = ACCOUNT_DETAIL_SCREEN; drawAccountDetailScreen();
        } else {
          vaultAccounts[selectedAccount] = old;
          setStatus("Save failed; previous vault kept", 2500); drawAddAccountScreen();
        }
      } else {
        if (vaultAccountCount >= MAX_ACCOUNTS) { setStatus("Account limit reached", 2200); drawAddAccountScreen(); return; }
        vaultAccounts[vaultAccountCount].site = editSite;
        vaultAccounts[vaultAccountCount].user = editUser;
        vaultAccounts[vaultAccountCount].password = editPassword;
        vaultAccountCount++;
        if (saveAllAccounts()) {
          selectedAccount = vaultAccountCount - 1;
          editSite = ""; editUser = ""; editPassword = "";
          secureClearGeneratedPassword();
          Serial.println("Add Account: new credential saved encrypted.");
          currentScreen = MY_ACCOUNTS_SCREEN; drawAccountsScreen();
        } else {
          if (vaultAccountCount) vaultAccountCount--;
          setStatus("Save failed; previous vault kept", 2500); drawAddAccountScreen();
        }
      }
      return;
    }
    bool wasEditing = editingExistingAccount;
    editSite = ""; editUser = ""; editPassword = "";
    secureClearGeneratedPassword();
    editingExistingAccount = false;
    if (wasEditing) {
      currentScreen = ACCOUNT_DETAIL_SCREEN; lastActivity = millis(); drawAccountDetailScreen();
    } else {
      currentScreen = HOME_SCREEN; lastActivity = millis(); drawHomeScreen();
    }
    return;
  }
}

void processSerialEntry() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      String line = serialLineBuffer; serialLineBuffer = ""; line.trim();
      if (currentScreen == ADD_ACCOUNT_SCREEN) {
        lastActivity = millis();
        if (line.startsWith("SITE=")) editSite = line.substring(5);
        else if (line.startsWith("USER=")) editUser = line.substring(5);
        else if (line.startsWith("PASS=")) editPassword = line.substring(5);
        else if (line == "NEXT") editField = (editField + 1) % 3;
        else if (line == "CLEAR") { editSite = ""; editUser = ""; editPassword = ""; }
        else if (line == "SHOW") Serial.println("Entry fields are masked on-screen; do not share this serial log.");
        else Serial.println("Serial entry commands: SITE=value, USER=value, PASS=value, NEXT, CLEAR");
        drawAddAccountScreen();
      }
    } else if (serialLineBuffer.length() < 120) serialLineBuffer += c;
  }
}

// =================================================
// SETUP
// =================================================

void setup() {
  Serial.begin(115200);
  delay(500);
  analogReadResolution(12);
  analogSetPinAttenuation(BATTERY_ADC_PIN, ADC_11db);
  updateBatteryReading();

  bleKeyboard.begin();
  bleKeyboardStarted = true;
  Serial.println("BLE HID keyboard initialised. Pair with ES3C28P Vault from your phone Bluetooth settings.");

  pinMode(TOUCH_PIN, INPUT);

  // Start R307S UART1.
  FingerSerial.begin(57600, SERIAL_8N1, FP_RX, FP_TX);
  finger.begin(57600);
  delay(300);

  fingerprintReady = finger.verifyPassword();

  Serial.println();
  Serial.println("ES3C28P Password Vault - Stage 7 AOA Add Over Air");

  if (fingerprintReady) {
    Serial.println("R307S detected successfully.");

    if (finger.getParameters() == FINGERPRINT_OK) {
      Serial.printf(
        "Sensor capacity: %u\n", finger.capacity
      );
      Serial.printf(
        "Sensor security level: %u\n",
        finger.security_level
      );
    }
  } else {
    Serial.println("R307S NOT detected.");
    Serial.println("PIN fallback will remain available.");
  }

  // Display colours
  BG = lcd.color565(15, 22, 35);
  PANEL = lcd.color565(35, 48, 66);
  WHITE = lcd.color565(245, 248, 255);
  MUTED = lcd.color565(165, 180, 200);
  CYAN = lcd.color565(70, 220, 240);
  RED = lcd.color565(255, 95, 100);
  GREEN = lcd.color565(90, 230, 150);
  BORDER = lcd.color565(75, 100, 125);

  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, HIGH);

  pinMode(TOUCH_RST, OUTPUT);
  digitalWrite(TOUCH_RST, LOW);
  delay(10);
  digitalWrite(TOUCH_RST, HIGH);
  delay(300);

  pinMode(TOUCH_INT, INPUT);

  Wire.begin(TOUCH_SDA, TOUCH_SCL);
  Wire.setClock(100000);

  lcd.init();
  lcd.setRotation(0);
  lcd.setColorDepth(16);
  lcd.setBrightness(255);

  // Register AOA routes once; the handlers expose add-only functionality.
  aoaServer.on("/", HTTP_GET, handleAOARoot);
  aoaServer.on("/login", HTTP_POST, handleAOALogin);
  aoaServer.on("/add", HTTP_POST, handleAOAAdd);
  aoaServer.on("/ping", HTTP_GET, handleAOAPing);
  aoaServer.onNotFound(handleAOANotFound);

  // Initialize encrypted microSD storage without formatting the card.
  vaultStorageReady = initVaultStorage();
  Serial.printf("Encrypted storage: %s\n", vaultStorageReady ? "ready" : "unavailable");

  Wire.beginTransmission(TOUCH_ADDR);
  touchAvailable = (Wire.endTransmission() == 0);

  Serial.printf(
    "Touch controller: %s\n",
    touchAvailable ? "detected" : "NOT detected"
  );

  lastActivity = millis();
  fingerprintWaitingForRemoval = false;

  if (touchAvailable) {
    currentScreen = FINGERPRINT_SCREEN;
    drawFingerprintScreen();
  } else {
    lcd.fillScreen(BG);
    lcd.setTextDatum(middle_center);
    lcd.setTextColor(RED, BG);
    lcd.setTextSize(2);
    lcd.drawString("Touch not found", 120, 140);
    Serial.println("Check touchscreen I2C configuration.");
  }
}

// =================================================
// MAIN LOOP
// =================================================

void loop() {
  if (!touchAvailable) {
    delay(100);
    return;
  }

  static unsigned long lastBatteryUpdate = 0;

  if (millis() - lastBatteryUpdate >= 30000) {
  lastBatteryUpdate = millis();

  updateBatteryReading();

  // Update only the battery indicator, not the entire page
  drawBatteryIndicator();
  }

  processSerialEntry();
  serviceAOA();

  // Read touchscreen.
  uint16_t x, y;
  bool touching = readTouch(x, y);

  // Process only the start of each touch.
  if (touching && !fingerDown) {
    fingerDown = true;
    lastActivity = millis();

    if (currentScreen == FINGERPRINT_SCREEN) {
      handleFingerprintTouch(x, y);
    } else if (currentScreen == PIN_SCREEN) {
      handlePINTouch(x, y);
    } else if (currentScreen == MY_ACCOUNTS_SCREEN) {
      handleAccountsTouch(x, y);
    } else if (currentScreen == ACCOUNT_DETAIL_SCREEN) {
      handleAccountDetailTouch(x, y);
    } else if (currentScreen == ADD_ACCOUNT_SCREEN) {
      handleAddAccountTouch(x, y);
    } else if (currentScreen == DELETE_CONFIRM_SCREEN) {
      handleDeleteConfirmTouch(x, y);
    } else if (currentScreen == AOA_QR_SCREEN) {
      handleAOAQRScreenTouch(x, y);
    } else if (currentScreen == GENERATE_SCREEN) {
      handleGenerateTouch(x, y);
    } else {
      handleHomeTouch(x, y);
    }
  } else if (!touching) {
    fingerDown = false;
  }

  // Fingerprint polling is active only on its screen.
  pollFingerprint();

  // Refresh expired messages.
  if (statusMessage.length() > 0 &&
      (int32_t)(millis() - statusUntil) >= 0) {
    statusMessage = "";

    if (currentScreen == FINGERPRINT_SCREEN) {
      drawFingerprintScreen();
    } else if (currentScreen == PIN_SCREEN) {
      drawPINScreen();
    }
  }

  // Auto-lock every unlocked screen after inactivity.
  if ((currentScreen == HOME_SCREEN ||
       currentScreen == MY_ACCOUNTS_SCREEN ||
       currentScreen == ACCOUNT_DETAIL_SCREEN ||
       currentScreen == ADD_ACCOUNT_SCREEN ||
       currentScreen == DELETE_CONFIRM_SCREEN ||
       currentScreen == AOA_QR_SCREEN ||
       currentScreen == GENERATE_SCREEN) &&
      millis() - lastActivity >= AUTO_LOCK_MS) {
    lockVault();
  }

  delay(10);
}
