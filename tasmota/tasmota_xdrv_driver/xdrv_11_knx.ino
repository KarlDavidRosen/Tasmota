/*
  xdrv_11_knx.ino - KNX IP Protocol support for Tasmota

  Copyright (C) 2021  Adrian Scillato  (https://github.com/ascillato)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef USE_KNX

// Forward declarations for the tunnel transport (implemented further down in this file)
void KnxTunnelLoop(void);
bool KnxTunnelConnected(void);
bool KnxTunnelSendDpt1Write(uint16_t ga, uint8_t value);
static bool KnxTunnelSendDpt1Response(uint16_t ga, uint8_t value);
bool KnxTunnelSendDpt5Write(uint16_t ga, uint8_t value);
bool KnxTunnelSendDpt5Response(uint16_t ga, uint8_t value);
bool KnxTunnelSendDpt9Write(uint16_t ga, float value);
bool KnxTunnelSendDpt9Response(uint16_t ga, float value);
bool KnxTunnelSendDpt14Write(uint16_t ga, float value);
bool KnxTunnelSendDpt14Response(uint16_t ga, float value);
bool KnxTunnelSendGroupValueRead(uint16_t ga);
void KnxTunnelDisconnectNow(void);

// Fast check used by KNX_Send_* to decide whether to use KNXnet/IP tunneling.
// Kept inlined/cheap to avoid repeating SettingsText() lookups inside enhancement repeat loops.
static inline bool KnxTunnelUseForWrite(knx_command_type_t ct) {
  // Use tunnel for GroupValue_Write and GroupValue_Response (answers to reads)
  if ((ct != KNX_CT_WRITE) && (ct != KNX_CT_ANSWER)) { return false; }
  const char* host = SettingsText(SET_KNX_TUNNEL_HOST);
  return (host && host[0] && KnxTunnelConnected());
}


static void KnxTunnelRxDpt1(uint16_t dst_ga, uint8_t value, uint8_t apci);

/*********************************************************************************************\
 * KNX support
 *
 * Using libraries:
 *   ESP KNX IP library (https://github.com/envy/esp-knx-ip)

Constants in tasmota.h
-----------------------

#define MAX_KNX_GA             10            Max number of KNX Group Addresses to read that can be set
#define MAX_KNX_CB             10            Max number of KNX Group Addresses to write that can be set
                                             If you change MAX_KNX_CB you also have to change on the esp-knx-ip.h file the following:
                                                       #define MAX_CALLBACK_ASSIGNMENTS  10
                                                       #define MAX_CALLBACKS             10
                                             Both to MAX_KNX_CB

Variables in settings.h
-----------------------

bool          Settings->flag.knx_enabled             Enable/Disable KNX Protocol
uint16_t      Settings->knx_physsical_addr           Physical KNX address of this device
uint8_t       Settings->knx_GA_registered            Number of group address to read
uint8_t       Settings->knx_CB_registered            Number of group address to write
uint16_t      Settings->knx_GA_addr[MAX_KNX_GA]      Group address to read
uint16_t      Settings->knx_CB_addr[MAX_KNX_CB]      Group address to write
uint8_t       Settings->knx_GA_param[MAX_KNX_GA]     Type of Input (relay changed, button pressed, sensor read)
uint8_t       Settings->knx_CB_param[MAX_KNX_CB]     Type of Output (set relay, toggle relay, reply sensor value)

\*********************************************************************************************/

#define XDRV_11  11

#include <esp-knx-ip.h>         // KNX Library

// Forward declarations / globals for KNXnet/IP tunneling (must be visible before any tunnel code uses them)
static bool KnxTnlConnectPending = false;
static void KnxTunnelSendDisconnectRequest(uint8_t ch);
static void KnxTunnelLoadSettings(void);

// Persistent tunnel configuration:
// - host stored in SettingsText(SET_KNX_TUNNEL_HOST)
// - port stored in Settings->knx_tunnel_port
static inline const char* KnxTunnelCfgHost(void) {
  return SettingsText(SET_KNX_TUNNEL_HOST);
}

static inline String KnxTunnelCfgHostEscaped(void) {
  return HtmlEscape(SettingsText(SET_KNX_TUNNEL_HOST));
}

static inline uint16_t KnxTunnelCfgPort(void) {
  return Settings->knx_tunnel_port ? Settings->knx_tunnel_port : 3671;
}

static inline String KnxTunnelCfgPortString(void) {
  return String(KnxTunnelCfgPort());
}

static void KnxTunnelSetConfig(const char* host, uint16_t port) {
  SettingsUpdateText(SET_KNX_TUNNEL_HOST, host ? host : "");
  Settings->knx_tunnel_port = port ? port : 3671;
}

#define TOGGLE_INHIBIT_TIME 15  // 15*50mseg = 750mseg (inhibit time for not toggling again relays by a KNX toggle command)

#ifndef KNX_ENHANCEMENT_REPEAT
#define KNX_ENHANCEMENT_REPEAT 3
#endif

#define KNX_Empty 255

typedef struct __device_parameters
{
  uint8_t type;        // PARAMETER_ID. Used as type of GA = relay, button, sensor, etc, (INPUTS)
                       // used when an action on device triggers a MSG to send on KNX
                       // Needed because this is the value that the ESP_KNX_IP library will pass as parameter
                       // to identify the action to perform when a MSG is received

  bool show;           // HARDWARE related. to identify if the parameter exists on the device.

  bool last_state;     // LAST_STATE of relays

  callback_id_t CB_id; // ACTION_ID. To store the ID value of Registered_CB to the library.
                       // The ESP_KNX_IP requires to register the callbacks, and then, to assign an address to the registered callback
                       // So CB_id is needed to store the ID of the callback to then, assign multiple addresses to the same ID (callback)
                       // It is used as type of CB = set relay, toggle relay, reply sensor, etc, (OUTPUTS)
                       // used when a MSG receive  KNX triggers an action on the device
                       // - Multiples address to the same callback (i.e. Set Relay 1 Status) are used on scenes for example
} device_parameters_t;

// device parameters (information that can be sent)
device_parameters_t device_param[] = {
  {  1, false, false, KNX_Empty }, // device_param[ 0] = Relay 1
  {  2, false, false, KNX_Empty }, // device_param[ 1] = Relay 2
  {  3, false, false, KNX_Empty }, // device_param[ 2] = Relay 3
  {  4, false, false, KNX_Empty }, // device_param[ 3] = Relay 4
  {  5, false, false, KNX_Empty }, // device_param[ 4] = Relay 5
  {  6, false, false, KNX_Empty }, // device_param[ 5] = Relay 6
  {  7, false, false, KNX_Empty }, // device_param[ 6] = Relay 7
  {  8, false, false, KNX_Empty }, // device_param[ 7] = Relay 8
  {  9, false, false, KNX_Empty }, // device_param[ 8] = Button 1
  { 10, false, false, KNX_Empty }, // device_param[ 9] = Button 2
  { 11, false, false, KNX_Empty }, // device_param[10] = Button 3
  { 12, false, false, KNX_Empty }, // device_param[11] = Button 4
  { 13, false, false, KNX_Empty }, // device_param[12] = Button 5
  { 14, false, false, KNX_Empty }, // device_param[13] = Button 6
  { 15, false, false, KNX_Empty }, // device_param[14] = Button 7
  { 16, false, false, KNX_Empty }, // device_param[15] = Button 8
  { KNX_TEMPERATURE, false, false, KNX_Empty }, // device_param[16] = Temperature
  { KNX_HUMIDITY   , false, false, KNX_Empty }, // device_param[17] = humidity
  { KNX_ENERGY_VOLTAGE   , false, false, KNX_Empty },
  { KNX_ENERGY_CURRENT   , false, false, KNX_Empty },
  { KNX_ENERGY_POWER   , false, false, KNX_Empty },
  { KNX_ENERGY_POWERFACTOR   , false, false, KNX_Empty },
  { KNX_ENERGY_DAILY   , false, false, KNX_Empty },
  { KNX_ENERGY_YESTERDAY   , false, false, KNX_Empty },
  { KNX_ENERGY_TOTAL   , false, false, KNX_Empty },
  { KNX_SLOT1 , false, false, KNX_Empty },
  { KNX_SLOT2 , false, false, KNX_Empty },
  { KNX_SLOT3 , false, false, KNX_Empty },
  { KNX_SLOT4 , false, false, KNX_Empty },
  { KNX_SLOT5 , false, false, KNX_Empty },
  { KNX_SCENE , false, false, KNX_Empty },
  { KNX_DIMMER , false, false, KNX_Empty },
  { KNX_COLOUR , false, false, KNX_Empty },
  { KNX_SLOT6 , false, false, KNX_Empty },
  { KNX_SLOT7 , false, false, KNX_Empty },
  { KNX_SLOT8 , false, false, KNX_Empty },
  { KNX_SLOT9 , false, false, KNX_Empty },
  { KNX_Empty, false, false, KNX_Empty}
};

// device parameters (information that can be sent)
const char * device_param_ga[] = {
  D_TIMER_OUTPUT  " 1",   // Relay 1
  D_TIMER_OUTPUT  " 2",   // Relay 2
  D_TIMER_OUTPUT  " 3",   // Relay 3
  D_TIMER_OUTPUT  " 4",   // Relay 4
  D_TIMER_OUTPUT  " 5",   // Relay 5
  D_TIMER_OUTPUT  " 6",   // Relay 6
  D_TIMER_OUTPUT  " 7",   // Relay 7
  D_TIMER_OUTPUT  " 8",   // Relay 8
  D_SENSOR_BUTTON " 1",   // Button 1
  D_SENSOR_BUTTON " 2",   // Button 2
  D_SENSOR_BUTTON " 3",   // Button 3
  D_SENSOR_BUTTON " 4",   // Button 4
  D_SENSOR_BUTTON " 5",   // Button 5
  D_SENSOR_BUTTON " 6",   // Button 6
  D_SENSOR_BUTTON " 7",   // Button 7
  D_SENSOR_BUTTON " 8",   // Button 8
  D_TEMPERATURE       ,   // Temperature
  D_HUMIDITY          ,   // Humidity
  D_VOLTAGE           ,
  D_CURRENT           ,
  D_POWERUSAGE        ,
  D_POWER_FACTOR      ,
  D_ENERGY_TODAY      ,
  D_ENERGY_YESTERDAY  ,
  D_ENERGY_TOTAL      ,
  D_KNX_TX_SLOT   " 1",
  D_KNX_TX_SLOT   " 2",
  D_KNX_TX_SLOT   " 3",
  D_KNX_TX_SLOT   " 4",
  D_KNX_TX_SLOT   " 5",
  D_KNX_TX_SCENE      ,
  D_BRIGHTLIGHT       ,
  D_COLOR             ,
  D_KNX_TX_SLOT   " 6",
  D_KNX_TX_SLOT   " 7",
  D_KNX_TX_SLOT   " 8",
  D_KNX_TX_SLOT   " 9",
  nullptr
};

// device actions (posible actions to be performed on the device)
const char *device_param_cb[] = {
  D_TIMER_OUTPUT " 1", // Set Relay 1 (1-On or 0-OFF)
  D_TIMER_OUTPUT " 2",
  D_TIMER_OUTPUT " 3",
  D_TIMER_OUTPUT " 4",
  D_TIMER_OUTPUT " 5",
  D_TIMER_OUTPUT " 6",
  D_TIMER_OUTPUT " 7",
  D_TIMER_OUTPUT " 8",
  D_TIMER_OUTPUT " 1 " D_BUTTON_TOGGLE, // Relay 1 Toggle (1 or 0 will toggle)
  D_TIMER_OUTPUT " 2 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 3 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 4 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 5 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 6 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 7 " D_BUTTON_TOGGLE,
  D_TIMER_OUTPUT " 8 " D_BUTTON_TOGGLE,
  D_REPLY " " D_TEMPERATURE, // Reply Temperature
  D_REPLY " " D_HUMIDITY,    // Reply Humidity
  D_REPLY " " D_VOLTAGE           ,
  D_REPLY " " D_CURRENT           ,
  D_REPLY " " D_POWERUSAGE        ,
  D_REPLY " " D_POWER_FACTOR      ,
  D_REPLY " " D_ENERGY_TODAY      ,
  D_REPLY " " D_ENERGY_YESTERDAY  ,
  D_REPLY " " D_ENERGY_TOTAL      ,
  D_KNX_RX_SLOT   " 1",
  D_KNX_RX_SLOT   " 2",
  D_KNX_RX_SLOT   " 3",
  D_KNX_RX_SLOT   " 4",
  D_KNX_RX_SLOT   " 5",
  D_KNX_RX_SCENE      ,
  D_BRIGHTLIGHT       ,
  D_COLOR             ,
  D_KNX_RX_SLOT   " 6",
  D_KNX_RX_SLOT   " 7",
  D_KNX_RX_SLOT   " 8",
  D_KNX_RX_SLOT   " 9",
  nullptr
};

uint8_t knx_slot_xref[] = {
  KNX_SLOT1,
  KNX_SLOT2,
  KNX_SLOT3,
  KNX_SLOT4,
  KNX_SLOT5,
  KNX_SLOT6,
  KNX_SLOT7,
  KNX_SLOT8,
  KNX_SLOT9
};

uint8_t knx_select_nice_list[] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  KNX_TEMPERATURE -1,
  KNX_HUMIDITY -1,
  KNX_ENERGY_VOLTAGE -1,
  KNX_ENERGY_CURRENT -1,
  KNX_ENERGY_POWER -1,
  KNX_ENERGY_POWERFACTOR -1,
  KNX_ENERGY_DAILY -1,
  KNX_ENERGY_YESTERDAY -1,
  KNX_ENERGY_TOTAL -1,
  KNX_SLOT1 -1,
  KNX_SLOT2 -1,
  KNX_SLOT3 -1,
  KNX_SLOT4 -1,
  KNX_SLOT5 -1,
  KNX_SLOT6 -1,
  KNX_SLOT7 -1,
  KNX_SLOT8 -1,
  KNX_SLOT9 -1,
  KNX_SCENE -1,
  KNX_DIMMER -1,
  KNX_COLOUR -1
};

// Commands
#define D_PRFX_KNX "Knx"
#define D_CMND_KNXTXCMND "TxCmnd"
#define D_CMND_KNXTXVAL "TxVal"
#define D_CMND_KNX_ENABLED "Enabled"
#define D_CMND_KNX_ENHANCED "Enhanced"
#define D_CMND_KNX_PA "PA"
#define D_CMND_KNX_GA "GA"
#define D_CMND_KNX_CB "CB"
#define D_CMND_KNXTXSCENE "TxScene"
#define D_CMND_KNXTXFLOAT "TxFloat"    // 2 bytes float (DPT9)
#define D_CMND_KNXTXDOUBLE "TxDouble"  // 4 bytes float (DPT14)
#define D_CMND_KNXTXBYTE "TxByte"      // 1 byte unsigned (DPT5)

// Backward-compatible aliases (underscored names from earlier patch iterations)
#define D_CMND_KNXTXCMND_A "Tx_Cmnd"
#define D_CMND_KNXTXVAL_A "Tx_Val"
#define D_CMND_KNX_ENABLED_A "_Enabled"
#define D_CMND_KNX_ENHANCED_A "_Enhanced"
#define D_CMND_KNX_PA_A "_PA"
#define D_CMND_KNX_GA_A "_GA"
#define D_CMND_KNX_CB_A "_CB"
#define D_CMND_KNXTXSCENE_A "Tx_Scene"
#define D_CMND_KNXTXFLOAT_A "Tx_Float"
#define D_CMND_KNXTXDOUBLE_A "Tx_Double"
#define D_CMND_KNXTXBYTE_A "Tx_Byte"

const char kKnxCommands[] PROGMEM = D_PRFX_KNX "|"  // Prefix
  D_CMND_KNXTXCMND "|" D_CMND_KNXTXVAL "|" D_CMND_KNX_ENABLED "|" D_CMND_KNX_ENHANCED "|"
  D_CMND_KNX_PA "|" D_CMND_KNX_GA "|" D_CMND_KNX_CB "|" D_CMND_KNXTXSCENE "|"
  D_CMND_KNXTXFLOAT "|" D_CMND_KNXTXDOUBLE "|" D_CMND_KNXTXBYTE "|"
  D_CMND_KNXTXCMND_A "|" D_CMND_KNXTXVAL_A "|" D_CMND_KNX_ENABLED_A "|" D_CMND_KNX_ENHANCED_A "|"
  D_CMND_KNX_PA_A "|" D_CMND_KNX_GA_A "|" D_CMND_KNX_CB_A "|" D_CMND_KNXTXSCENE_A "|"
  D_CMND_KNXTXFLOAT_A "|" D_CMND_KNXTXDOUBLE_A "|" D_CMND_KNXTXBYTE_A;

void (* const KnxCommand[])(void) PROGMEM = {
  &CmndKnxTxCmnd, &CmndKnxTxVal, &CmndKnxEnabled, &CmndKnxEnhanced,
  &CmndKnxPa, &CmndKnxGa, &CmndKnxCb, &CmndKnxTxScene,
  &CmndKnxTxFloat, &CmndKnxTxDouble, &CmndKnxTxByte,
  // aliases
  &CmndKnxTxCmnd, &CmndKnxTxVal, &CmndKnxEnabled, &CmndKnxEnhanced,
  &CmndKnxPa, &CmndKnxGa, &CmndKnxCb, &CmndKnxTxScene,
  &CmndKnxTxFloat, &CmndKnxTxDouble, &CmndKnxTxByte};

  address_t KNX_physs_addr;  // Physical KNX address of this device
  address_t KNX_addr;        // KNX Address converter variable

struct Knx_t {
  float last_temp;
  float last_hum;
  uint8_t toggle_inhibit;
  bool started = false;
} Knx;

/*********************************************************************************************/

void KNX_Send_1bit(address_t const &receiver, uint8_t value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE) && KnxTunnelSendDpt1Write((uint16_t)receiver.value, value)) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendDpt1Response((uint16_t)receiver.value, value ? 1 : 0)) { break; }
    }
    knx.send_1bit(receiver, ct, value);
  }
}


#define KNX_WRITE_1BIT(r,v) KNX_Send_1bit((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_1BIT(r,v) KNX_Send_1bit((r),(v),KNX_CT_ANSWER)

// Receive hook from xdrv_11_knx_tunnel (DPT 1.001 only)

void KNX_Send_1byte_uint(address_t const &receiver, uint8_t value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE)  && KnxTunnelSendDpt5Write((uint16_t)receiver.value, value)) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendDpt5Response((uint16_t)receiver.value, value)) { break; }
    }
    knx.send_1byte_uint(receiver, ct, value);
  }
}


#define KNX_WRITE_1BYTE_UINT(r,v) KNX_Send_1byte_uint((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_1BYTE_UINT(r,v) KNX_Send_1byte_uint((r),(v),KNX_CT_ANSWER)

void KNX_Send_2byte_float(address_t const &receiver, float value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE)  && KnxTunnelSendDpt9Write((uint16_t)receiver.value, value)) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendDpt9Response((uint16_t)receiver.value, value)) { break; }
    }
    knx.send_2byte_float(receiver, ct, value);
  }
}


#define KNX_WRITE_2BYTE_FLOAT(r,v) KNX_Send_2byte_float((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_2BYTE_FLOAT(r,v) KNX_Send_2byte_float((r),(v),KNX_CT_ANSWER)

void KNX_Send_4byte_float(address_t const &receiver, float value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE)  && KnxTunnelSendDpt14Write((uint16_t)receiver.value, value)) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendDpt14Response((uint16_t)receiver.value, value)) { break; }
    }
    knx.send_4byte_float(receiver, ct, value);
  }
}


#define KNX_WRITE_4BYTE_FLOAT(r,v) KNX_Send_4byte_float((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_4BYTE_FLOAT(r,v) KNX_Send_4byte_float((r),(v),KNX_CT_ANSWER)

void KNX_Send_4byte_int(address_t const &receiver, int32_t value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  uint8_t payload[4] = { (uint8_t)((value >> 24) & 0xFF), (uint8_t)((value >> 16) & 0xFF),
                         (uint8_t)((value >> 8) & 0xFF), (uint8_t)(value & 0xFF) };
  while (repeat--)
  {
    if (use_tunnel) {
    if ((ct == KNX_CT_WRITE) && KnxTunnelSendGroupWrite(receiver.value, payload, 4)) { break; }
    if ((ct == KNX_CT_ANSWER) && KnxTunnelSendGroupResponse(receiver.value, payload, 4)) { break; }
  }
    knx.send_4byte_int(receiver, ct, value);
  }
}


#define KNX_WRITE_4BYTE_INT(r,v) KNX_Send_4byte_int((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_4BYTE_INT(r,v) KNX_Send_4byte_int((r),(v),KNX_CT_ANSWER)

void KNX_Send_4byte_uint(address_t const &receiver, uint32_t value, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  uint8_t payload[4] = { (uint8_t)((value >> 24) & 0xFF), (uint8_t)((value >> 16) & 0xFF),
                         (uint8_t)((value >> 8) & 0xFF), (uint8_t)(value & 0xFF) };
  while (repeat--)
  {
    if (use_tunnel) {
    if ((ct == KNX_CT_WRITE) && KnxTunnelSendGroupWrite(receiver.value, payload, 4)) { break; }
    if ((ct == KNX_CT_ANSWER) && KnxTunnelSendGroupResponse(receiver.value, payload, 4)) { break; }
  }
    knx.send_4byte_uint(receiver, ct, value);
  }
}


#define KNX_WRITE_4BYTE_UINT(r,v) KNX_Send_4byte_uint((r),(v),KNX_CT_WRITE)
#define KNX_ANSWER_4BYTE_UINT(r,v) KNX_Send_4byte_uint((r),(v),KNX_CT_ANSWER)

void KNX_Send_3byte_color(address_t const &receiver, uint8_t red, uint8_t green, uint8_t blue, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  uint8_t payload[3] = { red, green, blue };
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE)  && KnxTunnelSendGroupWrite((uint16_t)receiver.value, payload, sizeof(payload))) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendGroupResponse((uint16_t)receiver.value, payload, sizeof(payload))) { break; }
    }
    uint8_t buf[] = {0, red, green, blue};
    knx.send(receiver, ct, sizeof(buf), buf);
  }
}

void KNX_Send_3byte_color(address_t const &receiver, uint8_t *rgb, knx_command_type_t ct)
{
  if (!rgb) { return; }
  KNX_Send_3byte_color(receiver, rgb[0], rgb[1], rgb[2], ct);
}



#define KNX_WRITE_3BYTE_COLOR(r,rgb) KNX_Send_3byte_color((r),(rgb),KNX_CT_WRITE)
#define KNX_ANSWER_3BYTE_COLOR(r,rgb) KNX_Send_3byte_color((r),(rgb),KNX_CT_ANSWER)

void KNX_Send_6byte_color(address_t const &receiver, uint8_t red, uint8_t green, uint8_t blue, uint8_t white, knx_command_type_t ct) 
{
  uint8_t repeat = Settings->flag.knx_enable_enhancement ? KNX_ENHANCEMENT_REPEAT : 1;
  const bool use_tunnel = KnxTunnelUseForWrite(ct);
  uint8_t payload[6] = { red, green, blue, white, 0x00, 0x0F };
  while (repeat--)
  {
    if (use_tunnel) {
      if ((ct == KNX_CT_WRITE)  && KnxTunnelSendGroupWrite((uint16_t)receiver.value, payload, sizeof(payload))) { break; }
      if ((ct == KNX_CT_ANSWER) && KnxTunnelSendGroupResponse((uint16_t)receiver.value, payload, sizeof(payload))) { break; }
    }
    uint8_t buf[] = {0, red, green, blue, white, 0, 0x0F};
    knx.send(receiver, ct, sizeof(buf), buf);
  }
}

void KNX_Send_6byte_color(address_t const &receiver, uint8_t *rgbw, knx_command_type_t ct)
{
  if (!rgbw) { return; }
  KNX_Send_6byte_color(receiver, rgbw[0], rgbw[1], rgbw[2], rgbw[3], ct);
}



#define KNX_WRITE_6BYTE_COLOR(r,rgbw) KNX_Send_6byte_color((r),(rgbw),KNX_CT_WRITE)
#define KNX_ANSWER_6BYTE_COLOR(r,rgbw) KNX_Send_6byte_color((r),(rgbw),KNX_CT_ANSWER)

/*********************************************************************************************/

uint8_t KNX_GA_Search( uint8_t param, uint8_t start = 0 )
{
  for (uint32_t i = start; i < Settings->knx_GA_registered; ++i)
  {
    if ( Settings->knx_GA_param[i] == param )
    {
      if ( Settings->knx_GA_addr[i] != 0 ) // Relay has group address set? GA=0/0/0 can not be used as KNX address, so it is used here as a: not set value
      {
         if ( i >= start ) { return i; }
      }
    }
  }
  return KNX_Empty;
}


uint8_t KNX_CB_Search( uint8_t param, uint8_t start = 0 )
{
  for (uint32_t i = start; i < Settings->knx_CB_registered; ++i)
  {
    if ( Settings->knx_CB_param[i] == param )
    {
      if ( Settings->knx_CB_addr[i] != 0 )
      {
         if ( i >= start ) { return i; }
      }
    }
  }
  return KNX_Empty;
}


void KNX_ADD_GA( uint8_t GAop, uint8_t GA_FNUM, uint8_t GA_AREA, uint8_t GA_FDEF )
{
  // Check if all GA were assigned. If yes-> return
  if ( Settings->knx_GA_registered >= MAX_KNX_GA ) { return; }
  if ( GA_FNUM == 0 && GA_AREA == 0 && GA_FDEF == 0 ) { return; }

  // Assign a GA to that address
  Settings->knx_GA_param[Settings->knx_GA_registered] = GAop;
  KNX_addr.ga.area = GA_FNUM;
  KNX_addr.ga.line = GA_AREA;
  KNX_addr.ga.member = GA_FDEF;
  Settings->knx_GA_addr[Settings->knx_GA_registered] = KNX_addr.value;

  Settings->knx_GA_registered++;

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_ADD " GA #%d: %s " D_TO " %d/%d/%d"),
   Settings->knx_GA_registered,
   device_param_ga[GAop-1],
   GA_FNUM, GA_AREA, GA_FDEF );
}


void KNX_DEL_GA( uint8_t GAnum )
{

  uint8_t dest_offset = 0;
  uint8_t src_offset = 0;
  uint8_t len = 0;

  // Delete GA
  Settings->knx_GA_param[GAnum-1] = 0;

  if (GAnum == 1)
  {
    // start of array, so delete first entry
    src_offset = 1;
    // Settings->knx_GA_registered will be 1 in case of only one entry
    // Settings->knx_GA_registered will be 2 in case of two entries, etc..
    // so only copy anything, if there is it at least more then one element
    len = (Settings->knx_GA_registered - 1);
  }
  else if (GAnum == Settings->knx_GA_registered)
  {
    // last element, don't do anything, simply decrement counter
  }
  else
  {
    // somewhere in the middle
    // need to calc offsets

    // skip all prev elements
    dest_offset = GAnum -1 ; // GAnum -1 is equal to how many element are in front of it
    src_offset = dest_offset + 1; // start after the current element
    len = (Settings->knx_GA_registered - GAnum);
  }

  if (len > 0)
  {
    memmove(Settings->knx_GA_param + dest_offset, Settings->knx_GA_param + src_offset, len * sizeof(uint8_t));
    memmove(Settings->knx_GA_addr + dest_offset, Settings->knx_GA_addr + src_offset, len * sizeof(Settings->knx_GA_addr[0]));
  }

  Settings->knx_GA_registered--;

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_DELETE " GA #%d"),
    GAnum );
}


void KNX_ADD_CB( uint8_t CBop, uint8_t CB_FNUM, uint8_t CB_AREA, uint8_t CB_FDEF )
{
  // Check if all callbacks were assigned. If yes-> return
  if ( Settings->knx_CB_registered >= MAX_KNX_CB ) { return; }
  if ( CB_FNUM == 0 && CB_AREA == 0 && CB_FDEF == 0 ) { return; }

  // Check if a CB for CBop was registered on the ESP-KNX-IP Library
  if ( device_param[CBop-1].CB_id == KNX_Empty )
  {
    // if no, register the CB for CBop
    device_param[CBop-1].CB_id = knx.callback_register("", KNX_CB_Action, &device_param[CBop-1]);
      // KNX IP Library requires a parameter
      // to identify which action was requested on the KNX network
      // to be performed on this device (set relay, etc.)
      // Is going to be used device_param[j].type that stores the type number (1: relay 1, etc)
  }
  // Assign a callback to CB address
  Settings->knx_CB_param[Settings->knx_CB_registered] = CBop;
  KNX_addr.ga.area = CB_FNUM;
  KNX_addr.ga.line = CB_AREA;
  KNX_addr.ga.member = CB_FDEF;
  Settings->knx_CB_addr[Settings->knx_CB_registered] = KNX_addr.value;

  knx.callback_assign( device_param[CBop-1].CB_id, KNX_addr );

  Settings->knx_CB_registered++;

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_ADD " CB #%d: %d/%d/%d " D_TO " %s"),
   Settings->knx_CB_registered,
   CB_FNUM, CB_AREA, CB_FDEF,
   device_param_cb[CBop-1] );
}


void KNX_DEL_CB( uint8_t CBnum )
{
  uint8_t oldparam = Settings->knx_CB_param[CBnum-1];
  uint8_t dest_offset = 0;
  uint8_t src_offset = 0;
  uint8_t len = 0;

  // Delete assigment
  knx.callback_unassign(CBnum-1);
  Settings->knx_CB_param[CBnum-1] = 0;

  if (CBnum == 1)
  {
    // start of array, so delete first entry
    src_offset = 1;
    // Settings->knx_CB_registered will be 1 in case of only one entry
    // Settings->knx_CB_registered will be 2 in case of two entries, etc..
    // so only copy anything, if there is it at least more then one element
    len = (Settings->knx_CB_registered - 1);
  }
  else if (CBnum == Settings->knx_CB_registered)
  {
    // last element, don't do anything, simply decrement counter
  }
  else
  {
    // somewhere in the middle
    // need to calc offsets

    // skip all prev elements
    dest_offset = CBnum -1 ; // GAnum -1 is equal to how many element are in front of it
    src_offset = dest_offset + 1; // start after the current element
    len = (Settings->knx_CB_registered - CBnum);
  }

  if (len > 0)
  {
    memmove(Settings->knx_CB_param + dest_offset, Settings->knx_CB_param + src_offset, len * sizeof(uint8_t));
    memmove(Settings->knx_CB_addr + dest_offset, Settings->knx_CB_addr + src_offset, len * sizeof(Settings->knx_CB_addr[0]));
  }

  Settings->knx_CB_registered--;

  // Check if there is no other assigment to that callback. If there is not. delete that callback register
  if ( KNX_CB_Search( oldparam ) == KNX_Empty ) {
    knx.callback_deregister( device_param[oldparam-1].CB_id );
    device_param[oldparam-1].CB_id =  KNX_Empty;
  }

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_DELETE " CB #%d"), CBnum );
}


bool KNX_CONFIG_NOT_MATCH(void)
{
  // Check for configured parameters that the device does not have (module changed)
  for (uint32_t i = 0; i < KNX_MAX_device_param; ++i)
  {
    if ( !device_param[i].show ) { // device has this parameter ?
      // if not, search for all registered group address to this parameter for deletion

      // Checks all GA
      if ( KNX_GA_Search(i+1) != KNX_Empty ) { return true; }
      // Check all CB
      if ( i < 8 ) // check relays (i from 8 to 15 are toggle relays parameters)
      {
        if ( KNX_CB_Search(i+1) != KNX_Empty ) { return true; }
        if ( KNX_CB_Search(i+9) != KNX_Empty ) { return true; }
      }
      // check sensors and others
      if ( i > 15 )
      {
        if ( KNX_CB_Search(i+1) != KNX_Empty ) { return true; }
      }
    }
  }

  // Check for invalid or erroneous configuration (tasmota flashed without clearing the memory)
  for (uint32_t i = 0; i < Settings->knx_GA_registered; ++i)
  {
    if ( Settings->knx_GA_param[i] != 0 ) // the GA[i] have a parameter defined?
    {
      if ( Settings->knx_GA_addr[i] == 0 ) // the GA[i] with parameter have the 0/0/0 as address?
      {
         return true; // So, it is invalid. Reset KNX configuration
      }
    }
  }
  for (uint32_t i = 0; i < Settings->knx_CB_registered; ++i)
  {
    if ( Settings->knx_CB_param[i] != 0 ) // the CB[i] have a parameter defined?
    {
      if ( Settings->knx_CB_addr[i] == 0 ) // the CB[i] with parameter have the 0/0/0 as address?
      {
         return true; // So, it is invalid. Reset KNX configuration
      }
    }
  }

  return false;
}

/*********************************************************************************************/

void KNXStart(void)
{
  knx.start(nullptr);
  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_START));
}


void KNX_INIT(void)
{
  // Check for incompatible config
  if (Settings->knx_GA_registered > MAX_KNX_GA) { Settings->knx_GA_registered = MAX_KNX_GA; }
  if (Settings->knx_CB_registered > MAX_KNX_CB) { Settings->knx_CB_registered = MAX_KNX_CB; }

  // Set Physical KNX Address of the device
  KNX_physs_addr.value = Settings->knx_physsical_addr;
  knx.physical_address_set( KNX_physs_addr );

  // Read Configuration
  //   Check which relays, buttons and sensors where configured for this device
  //   and activate options according to the hardware
  /*
  for (uint32_t i = 0; i < 8; i++) {
    if (PinUsed(GPIO_REL1, i)) {
      device_param[i].show = true;
    }
  }
  */
  for (uint32_t i = 0; i < (TasmotaGlobal.devices_present <= 8 ? TasmotaGlobal.devices_present : 8); ++i) {
    device_param[i].show = true;
  }
  for (uint32_t i = 0; i < 4; i++) {
    if (PinUsed(GPIO_KEY1, i)) {
      device_param[8 + i].show = true;
    }
  }
  for (uint32_t i = 0; i < 8; i++) {
    if (PinUsed(GPIO_SWT1, i)) {
      device_param[8 + i].show = true;
    }
  }

  if (PinUsed(GPIO_DHT11) || PinUsed(GPIO_DHT22) || PinUsed(GPIO_SI7021)) {
    device_param[KNX_TEMPERATURE-1].show = true;
    device_param[KNX_HUMIDITY-1].show = true;
  }
  for (uint32_t i = 0; i < MAX_ADCS; i++) {
    if (PinUsed(GPIO_ADC_TEMP, i)) {
      device_param[KNX_TEMPERATURE-1].show = true;
    }
  }
#ifdef USE_DS18x20
  if (PinUsed(GPIO_DSB, GPIO_ANY)) {
    device_param[KNX_TEMPERATURE-1].show = true;
  }
#endif

  // Ensure tunneling settings are parsed from flash at boot.
  // We only *parse* here; actual connect is triggered on FUNC_NETWORK_UP.
  KnxTunnelLoadSettings();

#if defined(USE_ENERGY_SENSOR)
  // Any device with a Power Monitoring
  if ( TasmotaGlobal.energy_driver != ENERGY_NONE ) {
    device_param[KNX_ENERGY_POWER-1].show = true;
    device_param[KNX_ENERGY_DAILY-1].show = true;
    device_param[KNX_ENERGY_YESTERDAY-1].show = true;
    device_param[KNX_ENERGY_TOTAL-1].show = true;
    device_param[KNX_ENERGY_VOLTAGE-1].show = true;
    device_param[KNX_ENERGY_CURRENT-1].show = true;
    device_param[KNX_ENERGY_POWERFACTOR-1].show = true;
  }
#endif // USE_ENERGY_SENSOR

#if defined(USE_RULES) || defined(USE_SCRIPT)
  device_param[KNX_SLOT1-1].show = true;
  device_param[KNX_SLOT2-1].show = true;
  device_param[KNX_SLOT3-1].show = true;
  device_param[KNX_SLOT4-1].show = true;
  device_param[KNX_SLOT5-1].show = true;
  device_param[KNX_SLOT6-1].show = true;
  device_param[KNX_SLOT7-1].show = true;
  device_param[KNX_SLOT8-1].show = true;
  device_param[KNX_SLOT9-1].show = true;
  device_param[KNX_SCENE-1].show = true;
#endif // USE_RULES

#ifdef USE_LIGHT
  if (Light.subtype > LST_NONE) {
    device_param[KNX_DIMMER-1].show = true;
    if ((LST_RGB == Light.subtype) || (LST_RGBW == Light.subtype))
      device_param[KNX_COLOUR-1].show = true;
  }
#endif // USE_LIGHT

  // Delete from KNX settings all configuration is not anymore related to this device
  if (KNX_CONFIG_NOT_MATCH()) {
    Settings->knx_GA_registered = 0;
    Settings->knx_CB_registered = 0;
    AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_DELETE " " D_KNX_PARAMETERS));
  }

  // Register Group Addresses to listen to
  //     Search on the settings if there is a group address set for receive KNX messages for the type: device_param[j].type
  //     If there is, register the group address on the KNX_IP Library to Receive data for Executing Callbacks
  uint8_t j;
  for (uint32_t i = 0; i < Settings->knx_CB_registered; ++i)
  {
    j = Settings->knx_CB_param[i];
    if ( j > 0 )
    {
      device_param[j-1].CB_id = knx.callback_register("", KNX_CB_Action, &device_param[j-1]); // KNX IP Library requires a parameter
                                                                                              // to identify which action was requested on the KNX network
                                                                                              // to be performed on this device (set relay, etc.)
                                                                                              // Is going to be used device_param[j].type that stores the type number (1: relay 1, etc)
      KNX_addr.value = Settings->knx_CB_addr[i];
      knx.callback_assign( device_param[j-1].CB_id, KNX_addr );
    }
  }
}


void KNX_CB_Action(message_t const &msg, void *arg)
{
  device_parameters_t *chan = (device_parameters_t *)arg;
  if (!(Settings->flag.knx_enabled)) { return; }

  char tempchar[33];

  if (msg.data_len == 1) {
    // COMMAND
    sprintf(tempchar,"%d",msg.data[0]);
  } else if (chan->type == KNX_SCENE) {
    // VALUE
    uint8_t tempvar = knx.data_to_1byte_uint(msg.data);
    dtostrfd(tempvar,0,tempchar);
#ifdef USE_LIGHT
  } else if (chan->type == KNX_DIMMER) {
    // VALUE
    uint8_t tempvar = changeUIntScale(knx.data_to_1byte_uint(msg.data),0, 255, 0, 100);
    dtostrfd(tempvar,0,tempchar);
  } else if (chan->type == KNX_COLOUR) {
    // VALUE
    snprintf_P(tempchar, sizeof(tempchar), (Light.subtype == LST_RGB) ? PSTR("%02X%02X%02X"):PSTR("%02X%02X%02X%02X"), msg.data[1], msg.data[2], msg.data[3]);
#endif // USE_LIGHT
  } else {
    // VALUE
    float tempvar = knx.data_to_4byte_float(msg.data);
    dtostrfd(tempvar,2,tempchar);
  }
  AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX D_RECEIVED_FROM " %d/%d/%d " D_COMMAND " %s: %s " D_TO " %s"),
   msg.received_on.ga.area, msg.received_on.ga.line, msg.received_on.ga.member,
   (msg.ct == KNX_CT_WRITE) ? D_KNX_COMMAND_WRITE : (msg.ct == KNX_CT_READ) ? D_KNX_COMMAND_READ : D_KNX_COMMAND_OTHER,
   tempchar,
   device_param_cb[(chan->type)-1]);

  switch (msg.ct)
  {
    case KNX_CT_WRITE:
      if (chan->type < 9) // Set Relays
      {
        ExecuteCommandPower(chan->type, msg.data[0], SRC_KNX);
      }
      else if (chan->type < 17) // Toggle Relays
      {
        if (!Knx.toggle_inhibit) {
          ExecuteCommandPower((chan->type) -8, POWER_TOGGLE, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }

#if defined(USE_RULES) || defined(USE_SCRIPT)
      else if (((chan->type >= KNX_SLOT1) && (chan->type <= KNX_SLOT5)) ||
               ((chan->type >= KNX_SLOT6) && (chan->type <= KNX_SLOT9))) // KNX RX SLOTs (write command)
      {
        if (!Knx.toggle_inhibit) {
          uint32_t slot_offset = KNX_SLOT1;
          if (chan->type >= KNX_SLOT6) {
            slot_offset = KNX_SLOT6;
          }
          char command[35]; //4294967295.00  13chars + 17
          if (msg.data_len == 1) {
            // Command received
            snprintf_P(command, sizeof(command), PSTR("event KNXRX_CMND%d=%d"), ((chan->type) - slot_offset + 1 ), msg.data[0]);
          } else {
            // Value received
            snprintf_P(command, sizeof(command), PSTR("event KNXRX_VAL%d=%s"), ((chan->type) - slot_offset + 1 ), tempchar);
          }
          ExecuteCommand(command, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }
      else if (chan->type == KNX_SCENE)  // KNX RX SCENE SLOT (write command)
      {
        if (!Knx.toggle_inhibit) {
          char command[25];
          // Value received
          snprintf_P(command, sizeof(command), PSTR("event KNX_SCENE=%s"), tempchar);
          ExecuteCommand(command, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }
#endif // USE_RULES
#ifdef USE_LIGHT
      else if (chan->type == KNX_DIMMER)  // KNX RX DIMMER SLOT (write command)
      {
        if (!Knx.toggle_inhibit) {
          char command[25];
          // Value received
          snprintf_P(command, sizeof(command), PSTR("Dimmer %s"), tempchar);
          ExecuteCommand(command, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }
      else if (chan->type == KNX_COLOUR)  // KNX RX COLOUR_RGB/RGBW SLOT (write command)
      {
        if (!Knx.toggle_inhibit) {
          char command[25];
          // Value received
          snprintf_P(command, sizeof(command), PSTR("Color #%s"), tempchar);
          ExecuteCommand(command, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }
#endif // USE_LIGHT
      break;

    case KNX_CT_READ:
      if (chan->type < 9) // reply Relays status
        KNX_Send_1bit(msg.received_on, chan->last_state, KNX_CT_ANSWER);
      else if (chan->type == KNX_TEMPERATURE) // Reply Temperature
      {
        #ifdef KNX_USE_DPT9
        KNX_ANSWER_2BYTE_FLOAT(msg.received_on, Knx.last_temp);
        #else
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Knx.last_temp);
        #endif // KNX_USE_DPT9
      }
      else if (chan->type == KNX_HUMIDITY) // Reply Humidity
      {
        #ifdef KNX_USE_DPT9
        KNX_ANSWER_2BYTE_FLOAT(msg.received_on, Knx.last_hum);
        #else
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Knx.last_hum);
        #endif // KNX_USE_DPT9
      }
#if defined(USE_ENERGY_SENSOR)      
      else if (chan->type == KNX_ENERGY_VOLTAGE) // Reply KNX_ENERGY_VOLTAGE
      {
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Energy->voltage[0]);
      }
      else if (chan->type == KNX_ENERGY_CURRENT) // Reply KNX_ENERGY_CURRENT
      {
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Energy->current[0]);
      }
      else if (chan->type == KNX_ENERGY_POWER) // Reply KNX_ENERGY_POWER
      {
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Energy->active_power[0]);
      }
      else if (chan->type == KNX_ENERGY_POWERFACTOR) // Reply KNX_ENERGY_POWERFACTOR
      {
        KNX_ANSWER_4BYTE_FLOAT(msg.received_on, Energy->power_factor[0]);
      }
      else if (chan->type == KNX_ENERGY_YESTERDAY) // Reply KNX_ENERGY_YESTERDAY
      {
        KNX_ANSWER_4BYTE_INT(msg.received_on, round(1000.0 * Energy->yesterday_sum));
      }
      else if (chan->type == KNX_ENERGY_DAILY) // Reply KNX_ENERGY_DAILY
      {
        KNX_ANSWER_4BYTE_INT(msg.received_on, round(1000.0 * Energy->daily_sum));
      }
      else if (chan->type == KNX_ENERGY_TOTAL) // Reply KNX_ENERGY_TOTAL
      {
        KNX_ANSWER_4BYTE_INT(msg.received_on, round(1000.0 * Energy->total_sum));
      }
#endif // USE_ENERGY_SENSOR

#if defined(USE_RULES) || defined(USE_SCRIPT)

      else if (((chan->type >= KNX_SLOT1) && (chan->type <= KNX_SLOT5)) ||
               ((chan->type >= KNX_SLOT6) && (chan->type <= KNX_SLOT9))) // KNX RX SLOTs (read command)
      {
        if (!Knx.toggle_inhibit) {
          uint32_t slot_offset = KNX_SLOT1;
          if (chan->type >= KNX_SLOT6) {
            slot_offset = KNX_SLOT6;
          }
          char command[25];
          snprintf_P(command, sizeof(command), PSTR("event KNXRX_REQ%d"), ((chan->type) - slot_offset + 1 ) );
          ExecuteCommand(command, SRC_KNX);
          if (Settings->flag.knx_enable_enhancement) {
            Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME;
          }
        }
      }
#endif // USE_RULES
#ifdef USE_LIGHT
      else if (chan->type == KNX_DIMMER) // Reply KNX_DIMMER
      {
        uint8_t dimmer = changeUIntScale(light_state.getDimmer(), 0, 100, 0, 255);
        KNX_ANSWER_1BYTE_UINT(msg.received_on, dimmer);
      }
      else if (chan->type == KNX_COLOUR) // Reply KNX_COLOUR
      {
        if ( Light.subtype == LST_RGB) {
          KNX_ANSWER_3BYTE_COLOR(msg.received_on, Light.current_color);
        } else if ( Light.subtype == LST_RGBW) {
          KNX_ANSWER_6BYTE_COLOR(msg.received_on, Light.current_color);
        }
      }
#endif // USE_LIGHT
      break;
  }
}


// Power feedback writer.
// Dedupe repeated writes (common during boot/restores) unless forced (e.g. first publish after tunnel connect).
void KnxUpdatePowerStateEx(uint8_t device, power_t power_mask, bool force)
{
  if (!(Settings->flag.knx_enabled)) { return; }
  if (device == 0) { return; }
#ifdef ESP8266
  // devices_present exists on both ESP8266/ESP32 builds; keep guard minimal
#endif
  if (device > TasmotaGlobal.devices_present) { return; }

  const uint8_t new_state = bitRead(power_mask, device - 1); // power state (on/off)

  // Dedupe: don't spam identical feedback telegrams (especially at boot)
  if (!force && (device_param[device - 1].last_state == new_state)) {
    return;
  }

  device_param[device - 1].last_state = new_state;

  // Search all the registered GA that has that output (variable: device) as parameter
  uint8_t i = KNX_GA_Search(device);
  while (i != KNX_Empty) {
    KNX_addr.value = Settings->knx_GA_addr[i];
    KNX_WRITE_1BIT(KNX_addr, new_state);

    AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %d " D_SENT_TO " %d/%d/%d"),
           device_param_ga[device - 1], new_state,
           KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

    i = KNX_GA_Search(device, i + 1);
  }
}

// Backwards-compatible wrapper (original signature/semantics: pass the full power bitmask)
void KnxUpdatePowerState(uint8_t device, power_t power_mask)
{
  KnxUpdatePowerStateEx(device, power_mask, false);
}



#ifdef USE_LIGHT
void KnxUpdateLight()
{
  if (!(Settings->flag.knx_enabled)) { return; }

  uint8_t dimmer = light_state.getDimmer();
  uint8_t dim_knx = changeUIntScale(dimmer, 0, 100, 0, 255);

  for (uint32_t i = 0; i < Settings->knx_GA_registered; ++i)
  {
    KNX_addr.value = Settings->knx_GA_addr[i];
    if ( KNX_addr.value != 0 ) {
      switch(Settings->knx_GA_param[i]) {
        case KNX_DIMMER:
          KNX_WRITE_1BYTE_UINT(KNX_addr, dim_knx);
          AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s %d " D_SENT_TO " %d/%d/%d"),
            device_param_ga[KNX_DIMMER -1],
            dimmer,
            KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);
          break;
        case KNX_COLOUR:
          if ( Light.subtype == LST_RGB) {
            KNX_WRITE_3BYTE_COLOR(KNX_addr, Light.current_color);
          } else if ( Light.subtype == LST_RGBW) {
            KNX_WRITE_6BYTE_COLOR(KNX_addr, Light.current_color);
          }
          AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s %d,%d,%d,%d " D_SENT_TO " %d/%d/%d"),
            device_param_ga[KNX_COLOUR -1],
            Light.current_color[0], Light.current_color[1], Light.current_color[2], Light.current_color[3],
            KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);
          break;
      }
    }
  }
}
#endif // USE_LIGHT

void KnxSendButtonPower(void)
{
  if (!(Settings->flag.knx_enabled)) { return; }

  uint32_t key = (XdrvMailbox.payload >> 16) & 0xFF;
  uint32_t device = XdrvMailbox.payload & 0xFF;
  uint32_t state = (XdrvMailbox.payload >> 8) & 0xFF;
// key 0 = button_topic
// key 1 = switch_topic
// state 0 = off
// state 1 = on
// state 2 = toggle
// state 3 = hold
// state 9 = clear retain flag

// Search all the registered GA that has that output (variable: device) as parameter
  uint8_t i = KNX_GA_Search(device + 8);
  while ( i != KNX_Empty ) {
    KNX_addr.value = Settings->knx_GA_addr[i];
    KNX_WRITE_1BIT(KNX_addr, !(state == 0));

    AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %d " D_SENT_TO " %d/%d/%d"),
     device_param_ga[device + 7], !(state == 0),
     KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

    i = KNX_GA_Search(device + 8, i + 1);
  }
//  }
}


void KnxSensor(uint8_t sensor_type, float value)
{
  if (sensor_type == KNX_TEMPERATURE)
  {
    Knx.last_temp = value;
  } else if (sensor_type == KNX_HUMIDITY)
  {
    Knx.last_hum = value;
  }

  if (!(Settings->flag.knx_enabled)) { return; }

  uint8_t i = KNX_GA_Search(sensor_type);
  while ( i != KNX_Empty ) {
    KNX_addr.value = Settings->knx_GA_addr[i];
    switch(sensor_type) {
      case KNX_ENERGY_DAILY:
      case KNX_ENERGY_YESTERDAY:
      case KNX_ENERGY_TOTAL:
        KNX_WRITE_4BYTE_INT(KNX_addr, round(1000.0 * value));
        break;
      case KNX_TEMPERATURE:
      case KNX_HUMIDITY:
        #ifdef KNX_USE_DPT9
        KNX_WRITE_2BYTE_FLOAT(KNX_addr, value);
        #else
        KNX_WRITE_4BYTE_FLOAT(KNX_addr, value);
        #endif 
      default:
        KNX_WRITE_4BYTE_FLOAT(KNX_addr, value);
    }

    AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s " D_SENT_TO " %d/%d/%d"),
     device_param_ga[sensor_type -1],
     KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

    i = KNX_GA_Search(sensor_type, i+1);
  }
}


/*********************************************************************************************\
 * Presentation
\*********************************************************************************************/

#ifdef USE_WEBSERVER
#ifdef USE_KNX_WEB_MENU
const char HTTP_FORM_KNX[] PROGMEM =
  "<fieldset style='min-width:530px;'>"
  "<legend style='text-align:left;'><b>&nbsp;" D_KNX_PARAMETERS "&nbsp;</b></legend>"
  "<form method='post' action='kn'>"
  "<br><center>"
  "<b>" D_KNX_PHYSICAL_ADDRESS " </b>"
  "<input style='width:12%%;' type='number' name='area' min='0' max='15' value='%d'> . "
  "<input style='width:12%%;' type='number' name='line' min='0' max='15' value='%d'> . "
  "<input style='width:12%%;' type='number' name='member' min='0' max='255' value='%d'>"
  "<br><br>" D_KNX_PHYSICAL_ADDRESS_NOTE "<br><br>"
  "<label><input id='b1' type='checkbox'";

const char HTTP_FORM_KNX1[] PROGMEM =
  "><b>" D_KNX_ENABLE "</b></label>&emsp;<label><input id='b2' type='checkbox'";

const char HTTP_FORM_KNX2[] PROGMEM =
  "><b>" D_KNX_ENHANCEMENT "</b></label><br></center><br>"

  "<fieldset><center>"
  "<b>KNXnet/IP Tunnel (unsecure)</b><hr>"
  "Gateway <input style='width:45%%;' name='kth' placeholder='e.g. 10.10.40.30' value='%s'> &emsp;"
  "Port <input style='width:18%%;' name='ktp' type='number' min='1' max='65535' value='%s'>"
  "<br><small>Leave Gateway empty to disable tunneling (routing/multicast only).</small>"
  "</center></fieldset><br>"

  "<fieldset><center>"
  "<b>" D_KNX_GROUP_ADDRESS_TO_WRITE "</b><hr>"

  "<select name='GAop' style='width:25%%;'>";

const char HTTP_FORM_KNX_OPT[] PROGMEM =
  "<option value='%d'>%s</option>";

const char HTTP_FORM_KNX_GA[] PROGMEM =
  "<input style='width:12%%;' type='number' id='%s' min='0' max='31' value='0'> / "
  "<input style='width:12%%;' type='number' id='%s' min='0' max='7' value='0'> / "
  "<input style='width:12%%;' type='number' id='%s' min='0' max='255' value='0'> ";

const char HTTP_FORM_KNX_ADD_BTN[] PROGMEM =
  "<button type='submit' onclick='%s()' %s name='btn_add' value='%d' style='width:18%%;'>" D_ADD "</button><br><br>"
  "<table style='width:80%%; font-size: 14px;'><col width='250'><col width='30'>";

const char HTTP_FORM_KNX_ADD_TABLE_ROW[] PROGMEM =
  "<tr><td><b>%s -> %d / %d / %d </b></td>"
  "<td><button type='submit' name='btn_del_ga' value='%d' class='button bred'> " D_DELETE " </button></td></tr>";

const char HTTP_FORM_KNX3[] PROGMEM =
  "</table></center></fieldset><br>"
  "<fieldset><form method='post' action='kn'><center>"
  "<b>" D_KNX_GROUP_ADDRESS_TO_READ "</b><hr>";

const char HTTP_FORM_KNX4[] PROGMEM =
  "-> <select name='CBop' style='width:25%%;'>";

const char HTTP_FORM_KNX_ADD_TABLE_ROW2[] PROGMEM =
  "<tr><td><b>%d / %d / %d -> %s</b></td>"
  "<td><button type='submit' name='btn_del_cb' value='%d' class='button bred'> " D_DELETE " </button></td></tr>";

void HandleKNXConfiguration(void)
{
  if (!HttpCheckPriviledgedAccess()) { return; }

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_HTTP D_CONFIGURE_KNX));

  char tmp[100];
  String stmp;

  if ( Webserver->hasArg("save") ) {
    KNX_Save_Settings();
    HandleConfiguration();
  }
  else
  {
    if ( Webserver->hasArg("btn_add") ) {
      if ( Webserver->arg("btn_add") == "1" ) {

        stmp = Webserver->arg("GAop"); //option selected
        uint8_t GAop = stmp.toInt();
        stmp = Webserver->arg("GA_FNUM");
        uint8_t GA_FNUM = stmp.toInt();
        stmp = Webserver->arg("GA_AREA");
        uint8_t GA_AREA = stmp.toInt();
        stmp = Webserver->arg("GA_FDEF");
        uint8_t GA_FDEF = stmp.toInt();

        if (GAop) {
          KNX_ADD_GA( GAop, GA_FNUM, GA_AREA, GA_FDEF );
        }
      }
      else
      {

        stmp = Webserver->arg("CBop"); //option selected
        uint8_t CBop = stmp.toInt();
        stmp = Webserver->arg("CB_FNUM");
        uint8_t CB_FNUM = stmp.toInt();
        stmp = Webserver->arg("CB_AREA");
        uint8_t CB_AREA = stmp.toInt();
        stmp = Webserver->arg("CB_FDEF");
        uint8_t CB_FDEF = stmp.toInt();

        if (CBop) {
          KNX_ADD_CB( CBop, CB_FNUM, CB_AREA, CB_FDEF );
        }
      }
    }
    else if ( Webserver->hasArg("btn_del_ga") )
    {

      stmp = Webserver->arg("btn_del_ga");
      uint8_t GA_NUM = stmp.toInt();

      KNX_DEL_GA(GA_NUM);

    }
    else if ( Webserver->hasArg("btn_del_cb") )
    {

      stmp = Webserver->arg("btn_del_cb");
      uint8_t CB_NUM = stmp.toInt();

      KNX_DEL_CB(CB_NUM);

    }

    WSContentStart_P(PSTR(D_CONFIGURE_KNX));
    WSContentSend_P(
      PSTR("function GAwarning()"
          "{"
            "var GA_FNUM=eb('GA_FNUM');"
            "var GA_AREA=eb('GA_AREA');"
            "var GA_FDEF=eb('GA_FDEF');"
            "if(GA_FNUM!=null&&GA_FNUM.value=='0'&&GA_AREA.value=='0'&&GA_FDEF.value=='0'){"
              "alert(\"" D_KNX_WARNING "\");"
            "}"
          "}"
          "function CBwarning()"
          "{"
            "var CB_FNUM=eb('CB_FNUM');"
            "var CB_AREA=eb('CB_AREA');"
            "var CB_FDEF=eb('CB_FDEF');"
            "if(CB_FNUM!=null&&CB_FNUM.value=='0'&&CB_AREA.value=='0'&&CB_FDEF.value=='0'){"
              "alert(\"" D_KNX_WARNING "\");"
            "}"
          "}"));
    WSContentSendStyle();
    KNX_physs_addr.value = Settings->knx_physsical_addr;
    WSContentSend_P(HTTP_FORM_KNX, KNX_physs_addr.pa.area, KNX_physs_addr.pa.line, KNX_physs_addr.pa.member);
    if ( Settings->flag.knx_enabled ) { WSContentSend_P(PSTR(" checked")); }
    WSContentSend_P(HTTP_FORM_KNX1);
    if ( Settings->flag.knx_enable_enhancement ) { WSContentSend_P(PSTR(" checked")); }

    WSContentSend_P(HTTP_FORM_KNX2, KnxTunnelCfgHostEscaped().c_str(), KnxTunnelCfgPortString().c_str());
    for (uint32_t i = 0; i < KNX_MAX_device_param ; i++)
    {
      if ( device_param[knx_select_nice_list[i]].show )
      {
        WSContentSend_P(HTTP_FORM_KNX_OPT, device_param[knx_select_nice_list[i]].type, device_param_ga[knx_select_nice_list[i]]);
      }
    }
    WSContentSend_P(PSTR("</select> -> "));
    WSContentSend_P(HTTP_FORM_KNX_GA, "GA_FNUM", "GA_AREA", "GA_FDEF");
    WSContentSend_P(HTTP_FORM_KNX_ADD_BTN, "GAwarning", (Settings->knx_GA_registered < MAX_KNX_GA) ? "" : "disabled", 1);
    for (uint32_t i = 0; i < Settings->knx_GA_registered ; ++i)
    {
      if ( Settings->knx_GA_param[i] )
      {
        KNX_addr.value = Settings->knx_GA_addr[i];
        WSContentSend_P(HTTP_FORM_KNX_ADD_TABLE_ROW, device_param_ga[Settings->knx_GA_param[i]-1], KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member, i +1);
      }
    }

    WSContentSend_P(HTTP_FORM_KNX3);
    WSContentSend_P(HTTP_FORM_KNX_GA, "CB_FNUM", "CB_AREA", "CB_FDEF");
    WSContentSend_P(HTTP_FORM_KNX4);

    uint8_t j;
    for (uint32_t i = 0; i < KNX_MAX_device_param ; i++)
    {
      // Check How many Relays are available and add: RelayX and TogleRelayX
      if ( (i > 8) && (i < 16) ) { j=i-8; } else { j=i; }
      if ( i == 8 ) { j = 0; }
      if ( device_param[knx_select_nice_list[j]].show )
      {
        WSContentSend_P(HTTP_FORM_KNX_OPT, device_param[knx_select_nice_list[i]].type, device_param_cb[knx_select_nice_list[i]]);
      }
    }
    WSContentSend_P(PSTR("</select> "));
    WSContentSend_P(HTTP_FORM_KNX_ADD_BTN, "CBwarning", (Settings->knx_CB_registered < MAX_KNX_CB) ? "" : "disabled", 2);

    for (uint32_t i = 0; i < Settings->knx_CB_registered ; ++i)
    {
      if ( Settings->knx_CB_param[i] )
      {
        KNX_addr.value = Settings->knx_CB_addr[i];
        WSContentSend_P(HTTP_FORM_KNX_ADD_TABLE_ROW2, KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member, device_param_cb[Settings->knx_CB_param[i]-1], i +1);
      }
    }
    WSContentSend_P(PSTR("</table></center></fieldset>"));
    WSContentSend_P(HTTP_FORM_END);
    WSContentSpaceButton(BUTTON_CONFIGURATION);
    WSContentStop();
  }

}


void KNX_Save_Settings(void)
{
  String stmp;
  address_t KNX_addr;

  Settings->flag.knx_enabled = Webserver->hasArg("b1");
  Settings->flag.knx_enable_enhancement = Webserver->hasArg("b2");
  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_ENABLED ": %d, " D_KNX_ENHANCEMENT ": %d"),
   Settings->flag.knx_enabled, Settings->flag.knx_enable_enhancement );

  stmp = Webserver->arg("area");
  KNX_addr.pa.area = stmp.toInt();
  stmp = Webserver->arg("line");
  KNX_addr.pa.line = stmp.toInt();
  stmp = Webserver->arg("member");
  KNX_addr.pa.member = stmp.toInt();
  Settings->knx_physsical_addr = KNX_addr.value;
  knx.physical_address_set( KNX_addr ); // Set Physical KNX Address of the device
  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX D_KNX_PHYSICAL_ADDRESS ": %d.%d.%d"),
   KNX_addr.pa.area, KNX_addr.pa.line, KNX_addr.pa.member );

  // Persist KNXnet/IP tunneling settings.
  // Empty host disables tunneling. Port defaults to 3671.
  String knx_tunnel_host = KnxTunnelCfgHost();
  uint16_t knx_tunnel_port = KnxTunnelCfgPort();

  if (Webserver->hasArg("kth")) {
    knx_tunnel_host = Webserver->arg("kth");
    knx_tunnel_host.trim();
  }
  if (Webserver->hasArg("ktp")) {
    stmp = Webserver->arg("ktp");
    stmp.trim();
    uint32_t port_tmp = stmp.length() ? strtoul(stmp.c_str(), nullptr, 10) : 3671;
    if ((port_tmp == 0) || (port_tmp > 65535)) { port_tmp = 3671; }
    knx_tunnel_port = (uint16_t)port_tmp;
  }

  KnxTunnelSetConfig(knx_tunnel_host.c_str(), knx_tunnel_port);
  KnxTunnelReloadFromSettings();

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX "GA: %d"),
   Settings->knx_GA_registered );
  for (uint32_t i = 0; i < Settings->knx_GA_registered ; ++i)
  {
    KNX_addr.value = Settings->knx_GA_addr[i];
    AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX "GA #%d: %s " D_TO " %d/%d/%d"),
     i+1, device_param_ga[Settings->knx_GA_param[i]-1],
     KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member );

  }

  AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX "CB: %d"),
   Settings->knx_CB_registered );
  for (uint32_t i = 0; i < Settings->knx_CB_registered ; ++i)
  {
    KNX_addr.value = Settings->knx_CB_addr[i];
    AddLog(LOG_LEVEL_DEBUG, PSTR(D_LOG_KNX "CB #%d: %d/%d/%d " D_TO " %s"),
     i+1,
     KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member,
     device_param_cb[Settings->knx_CB_param[i]-1] );
  }
}

#endif  // USE_KNX_WEB_MENU
#endif  // USE_WEBSERVER

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndKnxTxCmnd(void)
{
  // KNX_WRITE_1BIT
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNXTX_CMNDS) && (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled) {
    // XdrvMailbox.index <- KNX SLOT to use
    // XdrvMailbox.payload <- data to send
    // Search all the registered GA that has that output (variable: KNX SLOTx) as parameter
    uint8_t i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1]);
    while ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];
      KNX_WRITE_1BIT(KNX_addr, !(XdrvMailbox.payload == 0));

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %d " D_SENT_TO " %d/%d/%d"),
       device_param_ga[knx_slot_xref[XdrvMailbox.index -1] -1], !(XdrvMailbox.payload == 0),
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

      i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1], i + 1);
    }
    ResponseCmndIdxChar (XdrvMailbox.data );
  }
}

void CmndKnxTxVal(void)
{
  // KNX_WRITE_4BYTE_FLOAT
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNXTX_CMNDS) && (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled) {
    // Soft warning: Tx_Val uses float parser but historically used for integers too.
    // If user passes a decimal, recommend using KnxTxFloat/KnxTxDouble to avoid ambiguity/truncation.
    if (XdrvMailbox.data && (strchr(XdrvMailbox.data, '.') || strchr(XdrvMailbox.data, ','))) {
      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "Tx_Val received decimal '%s' - consider Tx_Float or Tx_Double"), XdrvMailbox.data);
    }

    // XdrvMailbox.index <- KNX SLOT to use
    // XdrvMailbox.payload <- data to send
    // Search all the registered GA that has that output (variable: KNX SLOTx) as parameter
    uint8_t i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1]);
    while ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];

      float tempvar = CharToFloat(XdrvMailbox.data);
      KNX_WRITE_4BYTE_FLOAT(KNX_addr, tempvar);

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %2_f " D_SENT_TO " %d/%d/%d"),
       device_param_ga[knx_slot_xref[XdrvMailbox.index -1] -1], &tempvar,
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

      i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1], i + 1);
    }
    ResponseCmndIdxChar (XdrvMailbox.data );
  }
}


void CmndKnxTxFloat(void)
{
  // KNX_WRITE_2BYTE_FLOAT
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNXTX_CMNDS) && (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled) {
    // XdrvMailbox.index <- KNX SLOT to use
    // XdrvMailbox.payload <- data to send
    // Search all the registered GA that has that output (variable: KNX SLOTx) as parameter
    uint8_t i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1]);
    while ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];

      float tempvar = CharToFloat(XdrvMailbox.data);
      KNX_WRITE_2BYTE_FLOAT(KNX_addr, tempvar);

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %2_f " D_SENT_TO " %d/%d/%d (2 bytes float)"),
       device_param_ga[knx_slot_xref[XdrvMailbox.index -1] -1], &tempvar,
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

      i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1], i + 1);
    }
    ResponseCmndIdxChar (XdrvMailbox.data );
  }
}

void CmndKnxTxDouble(void)
{
  // KNX_WRITE_4BYTE_FLOAT (DPT14)
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNXTX_CMNDS) && (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled) {
    // XdrvMailbox.index <- KNX SLOT to use
    // XdrvMailbox.payload <- data to send
    // Search all the registered GA that has that output (variable: KNX SLOTx) as parameter
    uint8_t i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1]);
    while ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];

      float tempvar = CharToFloat(XdrvMailbox.data);
      KNX_WRITE_4BYTE_FLOAT(KNX_addr, tempvar);

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %2_f " D_SENT_TO " %d/%d/%d (4 bytes float)"),
       device_param_ga[knx_slot_xref[XdrvMailbox.index -1] -1], &tempvar,
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

      i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1], i + 1);
    }
    ResponseCmndIdxChar (XdrvMailbox.data );
  }
}


void CmndKnxTxByte(void)
{
  // KNX_WRITE_1BYTE_UINT
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNXTX_CMNDS) && (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled) {
    // XdrvMailbox.index <- KNX SLOT to use
    // XdrvMailbox.payload <- data to send
    // Search all the registered GA that has that output (variable: KNX SLOTx) as parameter
    uint8_t i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1]);
    while ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];

      uint8_t tempvar = TextToInt(XdrvMailbox.data);
      KNX_WRITE_1BYTE_UINT(KNX_addr, tempvar);

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %d " D_SENT_TO " %d/%d/%d (1 byte unsigned)"),
       device_param_ga[knx_slot_xref[XdrvMailbox.index -1] -1], tempvar,
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);

      i = KNX_GA_Search(knx_slot_xref[XdrvMailbox.index -1], i + 1);
    }
    ResponseCmndIdxChar (XdrvMailbox.data );
  }
}

void CmndKnxTxScene(void)
{
  if ( (XdrvMailbox.data_len > 0) && Settings->flag.knx_enabled ) {
    // XdrvMailbox.payload <- scene number to send
    uint8_t i = KNX_GA_Search(KNX_SCENE);
    if ( i != KNX_Empty ) {
      KNX_addr.value = Settings->knx_GA_addr[i];

      uint8_t tempvar = TextToInt(XdrvMailbox.data);
      KNX_WRITE_1BYTE_UINT(KNX_addr, tempvar);

      AddLog(LOG_LEVEL_INFO, PSTR(D_LOG_KNX "%s = %d " D_SENT_TO " %d/%d/%d"),
       device_param_ga[KNX_SCENE-1], tempvar,
       KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member);
      ResponseCmndIdxChar (XdrvMailbox.data);
    }
  }
}

void CmndKnxEnabled(void)
{
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    Settings->flag.knx_enabled = XdrvMailbox.payload;
    if (!Settings->flag.knx_enabled) {
      Knx.started = false;
    }
  }
  ResponseCmndChar (GetStateText(Settings->flag.knx_enabled) );
}

void CmndKnxEnhanced(void)
{
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    Settings->flag.knx_enable_enhancement = XdrvMailbox.payload;
  }
  ResponseCmndChar (GetStateText(Settings->flag.knx_enable_enhancement) );
}

void CmndKnxPa(void)
{
  if (XdrvMailbox.data_len) {
    if (strchr(XdrvMailbox.data, '.') != nullptr) {  // Process parameter entry
      char sub_string[XdrvMailbox.data_len];

      int pa_area = atoi(subStr(sub_string, XdrvMailbox.data, ".", 1));
      int pa_line = atoi(subStr(sub_string, XdrvMailbox.data, ".", 2));
      int pa_member = atoi(subStr(sub_string, XdrvMailbox.data, ".", 3));

      if ( ((pa_area == 0) && (pa_line == 0) && (pa_member == 0))
            || (pa_area > 15) || (pa_line > 15) || (pa_member > 255) ) {
              return;  // Command Error
      }  // Invalid command

      KNX_addr.pa.area = pa_area;
      KNX_addr.pa.line = pa_line;
      KNX_addr.pa.member = pa_member;
      Settings->knx_physsical_addr = KNX_addr.value;
    }
  }
  KNX_addr.value = Settings->knx_physsical_addr;
  Response_P (PSTR("{\"%s\":\"%d.%d.%d\"}"),
    XdrvMailbox.command, KNX_addr.pa.area, KNX_addr.pa.line, KNX_addr.pa.member );
}

void CmndKnxGa(void)
{
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNX_GA)) {
    if (XdrvMailbox.data_len) {
      if (ArgC() > 1) {  // Process parameter entry
        char argument[XdrvMailbox.data_len];

        int ga_option = atoi(ArgV(argument, 1));
        int ga_area = atoi(ArgV(argument, 2));
        int ga_line = atoi(ArgV(argument, 3));
        int ga_member = atoi(ArgV(argument, 4));

        if ( ((ga_area == 0) && (ga_line == 0) && (ga_member == 0))
          || (ga_area > 31) || (ga_line > 7) || (ga_member > 255)
          || (ga_option < 0) || ((ga_option > KNX_MAX_device_param ) && (ga_option != KNX_Empty))
          || (!device_param[ga_option-1].show) ) {
               return;  // Command Error
        }  // Invalid command

        KNX_addr.ga.area = ga_area;
        KNX_addr.ga.line = ga_line;
        KNX_addr.ga.member = ga_member;

        if ( XdrvMailbox.index > Settings->knx_GA_registered ) {
          Settings->knx_GA_registered ++;
          XdrvMailbox.index = Settings->knx_GA_registered;
        }

        Settings->knx_GA_addr[XdrvMailbox.index -1] = KNX_addr.value;
        Settings->knx_GA_param[XdrvMailbox.index -1] = ga_option;
      } else {
        if ( (XdrvMailbox.payload <= Settings->knx_GA_registered) && (XdrvMailbox.payload > 0) ) {
          XdrvMailbox.index = XdrvMailbox.payload;
        } else {
          return;  // Command Error
        }
      }
      if ( XdrvMailbox.index <= Settings->knx_GA_registered ) {
        KNX_addr.value = Settings->knx_GA_addr[XdrvMailbox.index -1];
        Response_P (PSTR("{\"%s%d\":\"%s, %d/%d/%d\"}"),
          XdrvMailbox.command, XdrvMailbox.index, device_param_ga[Settings->knx_GA_param[XdrvMailbox.index-1]-1],
          KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member );
      }
    } else {
      ResponseCmndIdxNumber (Settings->knx_GA_registered );
    }
  }
}

void CmndKnxCb(void)
{
  if ((XdrvMailbox.index > 0) && (XdrvMailbox.index <= MAX_KNX_CB)) {
    if (XdrvMailbox.data_len) {
      if (ArgC() > 1) {  // Process parameter entry
        char argument[XdrvMailbox.data_len];

        int cb_option = atoi(ArgV(argument, 1));
        int cb_area = atoi(ArgV(argument, 2));
        int cb_line = atoi(ArgV(argument, 3));
        int cb_member = atoi(ArgV(argument, 4));

        if ( ((cb_area == 0) && (cb_line == 0) && (cb_member == 0))
          || (cb_area > 31) || (cb_line > 7) || (cb_member > 255)
          || (cb_option < 0) || ((cb_option > KNX_MAX_device_param ) && (cb_option != KNX_Empty))
          || (!device_param[cb_option-1].show) ) {
               return;  // Command Error
        }  // Invalid command

        KNX_addr.ga.area = cb_area;
        KNX_addr.ga.line = cb_line;
        KNX_addr.ga.member = cb_member;

        if ( XdrvMailbox.index > Settings->knx_CB_registered ) {
          Settings->knx_CB_registered ++;
          XdrvMailbox.index = Settings->knx_CB_registered;
        }

        Settings->knx_CB_addr[XdrvMailbox.index -1] = KNX_addr.value;
        Settings->knx_CB_param[XdrvMailbox.index -1] = cb_option;
      } else {
        if ( (XdrvMailbox.payload <= Settings->knx_CB_registered) && (XdrvMailbox.payload > 0) ) {
          XdrvMailbox.index = XdrvMailbox.payload;
        } else {
          return;  // Command Error
        }
      }
      if ( XdrvMailbox.index <= Settings->knx_CB_registered ) {
        KNX_addr.value = Settings->knx_CB_addr[XdrvMailbox.index -1];
        Response_P (PSTR("{\"%s%d\":\"%s, %d/%d/%d\"}"),
          XdrvMailbox.command, XdrvMailbox.index, device_param_cb[Settings->knx_CB_param[XdrvMailbox.index-1]-1],
          KNX_addr.ga.area, KNX_addr.ga.line, KNX_addr.ga.member );
      }
    } else {
      ResponseCmndIdxNumber (Settings->knx_CB_registered );
    }
  }
}

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv11(uint32_t function)
{
  bool result = false;
    switch (function) {
      case FUNC_LOOP:
        if (!TasmotaGlobal.global_state.network_down) {
          knx.loop();  // Process knx events (routing/multicast)
          KnxTunnelLoop();
        }
        break;
      case FUNC_EVERY_50_MSECOND:
        if (Knx.toggle_inhibit) {
          Knx.toggle_inhibit--;
        }
        break;
      case FUNC_ANY_KEY:
        KnxSendButtonPower();
        break;
#ifdef USE_WEBSERVER
#ifdef USE_KNX_WEB_MENU
      case FUNC_WEB_ADD_BUTTON:
        WSContentSend_P(HTTP_FORM_BUTTON, PSTR("kn"), PSTR(D_CONFIGURE_KNX));
        break;
      case FUNC_WEB_ADD_HANDLER:
        WebServer_on(PSTR("/kn"), HandleKNXConfiguration);
        break;
#endif // USE_KNX_WEB_MENU
#endif  // USE_WEBSERVER
      case FUNC_COMMAND:
        result = DecodeCommand(kKnxCommands, KnxCommand);
        break;
      case FUNC_PRE_INIT:
        KNX_INIT();
        break;
      case FUNC_NETWORK_UP:
        if (!Knx.started && Settings->flag.knx_enabled) {  // CMND_KNX_ENABLED
          KNXStart();
          Knx.started = true;
        }
        {
          // Start tunnel transport if configured (host not empty)
            const char* host = KnxTunnelCfgHost();
          
          if (host && host[0]) {
            // Parse settings again in case they were changed while offline.
            KnxTunnelLoadSettings();
            (void)KnxTunnelBegin();
          }
        }
        break;
      case FUNC_SAVE_BEFORE_RESTART:
	      #ifdef FUNC_PRE_OTA
	      case FUNC_PRE_OTA:
	      #endif
        // Best-effort: free the tunnel slot on the gateway before reboot/OTA.
        KnxTunnelDisconnectNow();
        break;
      case FUNC_NETWORK_DOWN:
        Knx.started = false;
        break;
//      case FUNC_SET_POWER:
//        break;
      case FUNC_ACTIVE:
        result = true;
        break;
    }
  return result;
}


/*********************************************************************************************\
 * KNXnet/IP tunnelling support (unsecure) – intended for 1Home IP Tunneling Server
 *
 * Configure in the KNX web page: Tunnel Host / Tunnel Port
 *
 * Notes:
 * - This implementation focuses on DPT 1.001 (1-bit switch) GroupValueWrite/Read/Response.
 * - When tunnel host is set and tunnel is connected, outgoing KNX telegrams are sent via tunnel.
 * - Incoming telegrams received via tunnel are mapped using the existing KNX callback table
\*********************************************************************************************/


#include <WiFiUdp.h>


static WiFiUDP KnxTnlUdp;

static IPAddress KnxTnlGwIp;
static uint16_t  KnxTnlGwPort = 3671;      // configured server port (usually 3671)
static uint16_t  KnxTnlSrvCtrlPort = 3671; // server control endpoint port (from CONNECT_RESPONSE)
static uint16_t  KnxTnlSrvDataPort = 3671; // server data endpoint port (from CONNECT_RESPONSE)

static uint8_t   KnxTnlChannel = 0;
static uint8_t   KnxTnlSeqTx = 0;
static uint8_t   KnxTnlSeqRxLast = 0xFF;
static uint16_t  KnxTnlAssignedIa = 0;   // 0x11FA etc, from CONNECT_RESPONSE (KNX individual address)
static uint32_t  KnxTnlLastRxMs = 0;
static uint32_t  KnxTnlLastCommMs = 0;
// Timestamp (millis) when CONNECT_RESPONSE was accepted; used for a short grace window
// to avoid false RX-timeout immediately after connecting.
static uint32_t  KnxTnlConnectedAtMs = 0;
static uint8_t   KnxTnlStateRetry = 0;

static uint32_t  KnxTnlLastConnTryMs = 0;
static uint32_t  KnxTnlLastKeepAliveMs = 0;
static bool      KnxTnlStatePending = false;

static uint32_t  KnxTnlLastStateReqMs = 0;
static uint32_t KnxTnlNextConnectMs = 0;
static uint16_t KnxTnlKeepaliveJitterMs = 0;  // 0..2000ms randomized on connect/OK responses
static bool      KnxTnlPublishPending = false;  // publish status once per successful tunnel connect

// --- TX reliability: strict stop-and-wait sequence handling (required by 1Home tunneling) ---
// Many KNXnet/IP tunneling servers only forward telegrams to the TP bus when the client
// respects the stop-and-wait semantics: send one TUNNELING_REQUEST, wait for TUNNELING_ACK OK,
// then increment sequence and send the next.
static uint8_t   KnxTnlTxNextSeq = 0;

#define KNX_TNL_TXQ_LEN 32
typedef struct {
  uint16_t len;
  uint8_t  cemi[64];
} KnxTnlTxQEntry_t;

static KnxTnlTxQEntry_t KnxTnlTxQ[KNX_TNL_TXQ_LEN];
static uint8_t KnxTnlTxQHead = 0;
static uint8_t KnxTnlTxQTail = 0;
static uint8_t KnxTnlTxQCount = 0;

typedef struct {
  bool     active;
  uint8_t  seq;
  uint8_t  tries;
  uint16_t pkt_len;
  uint8_t  pkt[96];
  uint32_t sent_ms;
} KnxTnlTxInFlight_t;

static KnxTnlTxInFlight_t KnxTnlTxInFlight = { false, 0, 0, 0, {0}, 0 };

static const uint32_t KNX_TNL_TX_ACK_TIMEOUT_MS = 1000;  // typical default
static const uint8_t  KNX_TNL_TX_MAX_RETRIES = 3;  // typical default

// --- Tunnel diagnostics counters (useful for verifying stability on strict gateways like 1Home) ---
static uint32_t KnxTnlStatTxReq = 0;
static uint32_t KnxTnlStatTxAckOk = 0;
static uint32_t KnxTnlStatTxAckErr = 0;
static uint32_t KnxTnlStatTxRetry = 0;
static uint32_t KnxTnlStatTxDrop = 0;
static uint32_t KnxTnlStatRxTunReq = 0;
static uint32_t KnxTnlStatRxTunAck = 0;
static uint32_t KnxTnlStatRxStateResp = 0;
static uint32_t KnxTnlStatReconnect = 0;
static uint32_t KnxTnlLastStatsMs = 0;

static void KnxTunnelStatsTick(void) {
  uint32_t now = millis();
  if (KnxTnlLastStatsMs == 0) { KnxTnlLastStatsMs = now; return; }
  if ((now - KnxTnlLastStatsMs) < 60000) { return; }  // once per minute
  KnxTnlLastStatsMs = now;

  AddLog(LOG_LEVEL_DEBUG,
         PSTR("KNX: Tnl stats tx=%u ack_ok=%u ack_err=%u retry=%u drop=%u rx_req=%u rx_ack=%u state=%u q=%u inflight=%u seq=%u"),
         (unsigned)KnxTnlStatTxReq, (unsigned)KnxTnlStatTxAckOk, (unsigned)KnxTnlStatTxAckErr,
         (unsigned)KnxTnlStatTxRetry, (unsigned)KnxTnlStatTxDrop,
         (unsigned)KnxTnlStatRxTunReq, (unsigned)KnxTnlStatRxTunAck, (unsigned)KnxTnlStatRxStateResp,
         (unsigned)KnxTnlTxQCount, (unsigned)(KnxTnlTxInFlight.active ? 1 : 0), (unsigned)KnxTnlTxNextSeq);
}

// Forward declarations
static void KnxTunnelTxTick(void);
static bool KnxTunnelTxEnqueue(const uint8_t *cemi, uint16_t cemi_len);

// Connection/keepalive tuning
// - Avoid hammering CONNECT_REQUEST (some gateways treat each as a new slot allocation)
// - Keep the same UDP local port while connected
// - Send CONNECTIONSTATE_REQUEST often enough to avoid idle timeouts
static const uint32_t KNX_TNL_CONNECT_RETRY_MS   = 10000;  // retry connect every 10s when not connected
static const uint32_t KNX_TNL_CONNECT_TIMEOUT_MS = 5000;   // if no CONNECT_RESPONSE in 5s, allow a retry
static const uint32_t KNX_TNL_CONNECT_GRACE_MS   = 1500;   // suppress RX-timeout checks right after CONNECT (ms)
static const uint32_t KNX_TNL_KEEPALIVE_MS = 30000;   // keepalive base interval (ms); kept < typical gateway timeout
static const uint32_t KNX_TNL_KEEPALIVE_RSP_TIMEOUT_MS = 10000;
static const uint8_t  KNX_TNL_KEEPALIVE_MAX_RETRIES = 3;  // per KNXnet/IP tunnelling spec // wait for CONNECTIONSTATE_RESPONSE before reconnecting
static const uint32_t KNX_TNL_RX_TIMEOUT_MS = 120000; // 2 minutes without any UDP traffic => reconnect


static char      KnxTnlHost[64] = {0};
static uint16_t  KnxTnlPort = 3671;
static uint16_t  KnxTnlLocalPort = 50000; // Used in CONNECT_REQUEST/CONNECTIONSTATE headers

static bool KnxTunnelConfigured(void) {
  // Host must be a literal IP address (avoid blocking DNS lookups on ESP core).
  return (KnxTnlHost[0] != 0) && (KnxTnlPort != 0) && ((uint32_t)KnxTnlGwIp != 0);
}

bool KnxTunnelConnected(void) {
  return (KnxTnlChannel != 0);
}

static void KnxTunnelReset(void) {
  // Best-effort clean disconnect to release server resources
  if (KnxTnlChannel) {
    KnxTunnelSendDisconnectRequest(KnxTnlChannel);
  }

  KnxTnlChannel = 0;
  KnxTnlSeqTx = 0;
  KnxTnlSeqRxLast = 0xFF;
  KnxTnlAssignedIa = 0;
  KnxTnlConnectPending = false;
  KnxTnlLastRxMs = millis();
  KnxTnlLastCommMs = KnxTnlLastRxMs;
  KnxTnlConnectedAtMs = 0;
  KnxTnlLastKeepAliveMs = 0;
  KnxTnlStatePending = false;
  KnxTnlStateRetry = 0;
  KnxTnlLastStateReqMs = 0;
  KnxTnlPublishPending = false;

  // TX state machine reset
  KnxTnlTxNextSeq = 0;
  KnxTnlTxQHead = KnxTnlTxQTail = KnxTnlTxQCount = 0;
  KnxTnlTxInFlight.active = false;
  KnxTnlTxInFlight.pkt_len = 0;
  KnxTnlTxInFlight.tries = 0;
  KnxTnlTxInFlight.sent_ms = 0;

  KnxTnlUdp.stop();
}

static uint16_t KnxTnlGroupAddrToU16(uint8_t main, uint8_t middle, uint8_t sub) {
  // 3-level GA: main(0..31), middle(0..7), sub(0..255) => 16-bit
  return (uint16_t)(((main & 0x1F) << 11) | ((middle & 0x07) << 8) | (sub & 0xFF));
}

static void KnxTunnelSendRawTo(const IPAddress &ip, uint16_t port, const uint8_t *buf, uint16_t len) {
#ifdef KNX_TNL_DEBUG_DUMP
  // Raw packet dump for debugging without external sniffers.
  AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Tnl tx raw len=%u"), len);
  // AddLogBuffer expects a mutable buffer. Use stack when possible to avoid heap churn.
  if (len <= 128) {
    uint8_t tmp[128];
    memcpy(tmp, buf, len);
    AddLogBuffer(LOG_LEVEL_DEBUG, tmp, len);
  } else {
    uint8_t *tmp = (uint8_t*)malloc(len);
    if (tmp) {
      memcpy(tmp, buf, len);
      AddLogBuffer(LOG_LEVEL_DEBUG, tmp, len);
      free(tmp);
    }
  }
#endif
  KnxTnlUdp.beginPacket(ip, port);
  KnxTnlUdp.write(buf, len);
  KnxTnlUdp.endPacket();
  KnxTnlLastCommMs = millis();
}

static void KnxTunnelSendRaw(const uint8_t *buf, uint16_t len) {
  // Default to configured port for legacy servers; most services will use the
  // ports learned from CONNECT_RESPONSE once connected.
  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlGwPort, buf, len);
}

static void KnxTunnelSendConnectRequest(void) {
  uint8_t pkt[26] = {0};
  // KNXnet/IP header
  pkt[0]=0x06; pkt[1]=0x10; pkt[2]=0x02; pkt[3]=0x05; // CONNECT_REQUEST
  pkt[4]=0x00; pkt[5]=0x1A;
  // HPAI control endpoint (UDP, local IP, local port)
  pkt[6]=0x08; pkt[7]=0x01;
  IPAddress lip = WiFi.localIP();
  pkt[8]=lip[0]; pkt[9]=lip[1]; pkt[10]=lip[2]; pkt[11]=lip[3];
  uint16_t lport = KnxTnlLocalPort;
  pkt[12]=(uint8_t)(lport>>8); pkt[13]=(uint8_t)(lport & 0xFF);
  // HPAI data endpoint (same)
  pkt[14]=0x08; pkt[15]=0x01;
  pkt[16]=lip[0]; pkt[17]=lip[1]; pkt[18]=lip[2]; pkt[19]=lip[3];
  pkt[20]=(uint8_t)(lport>>8); pkt[21]=(uint8_t)(lport & 0xFF);
  // CRI: tunnelling, link layer (0x02), reserved 0x00
  pkt[22]=0x04; pkt[23]=0x04; pkt[24]=0x02; pkt[25]=0x00;

  KnxTunnelSendRaw(pkt, sizeof(pkt));
}

static void KnxTunnelSendConnectionStateRequest(void) {
  if (!KnxTunnelConnected()) { return; }
  uint8_t pkt[16] = {0};
  pkt[0]=0x06; pkt[1]=0x10; pkt[2]=0x02; pkt[3]=0x07; // CONNECTIONSTATE_REQUEST
  pkt[4]=0x00; pkt[5]=0x10;
  pkt[6]=KnxTnlChannel; pkt[7]=0x00; // reserved
  pkt[8]=0x08; pkt[9]=0x01;
  IPAddress lip = WiFi.localIP();
  pkt[10]=lip[0]; pkt[11]=lip[1]; pkt[12]=lip[2]; pkt[13]=lip[3];
  uint16_t lport = KnxTnlLocalPort;
  pkt[14]=(uint8_t)(lport>>8); pkt[15]=(uint8_t)(lport & 0xFF);

  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvCtrlPort, pkt, sizeof(pkt));
}

static void KnxTunnelSendTunnellingAck(uint8_t ch, uint8_t seq) {
  // KNXnet/IP TUNNELING_ACK (0x0421)
  // Header(6) + ConnectionHeader(4): len=0x04, channel, seq, status
  uint8_t pkt[10] = {0};
  pkt[0]=0x06; pkt[1]=0x10; pkt[2]=0x04; pkt[3]=0x21; // TUNNELING_ACK
  pkt[4]=0x00; pkt[5]=0x0A;
  pkt[6]=0x04;       // connection header length
  pkt[7]=ch;         // channel id
  pkt[8]=seq;        // sequence number (mirrored)
  pkt[9]=0x00;       // status = OK
  // ACK must be sent to the server's data endpoint (not necessarily the configured port)
  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvDataPort, pkt, sizeof(pkt));
}

static bool KnxTunnelTxEnqueue(const uint8_t *cemi, uint16_t cemi_len) {
  if (!KnxTunnelConnected()) { return false; }
  if (!cemi || (cemi_len == 0) || (cemi_len > sizeof(KnxTnlTxQ[0].cemi))) { return false; }
  if (KnxTnlTxQCount >= KNX_TNL_TXQ_LEN) {
    AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel TX queue full, dropping cEMI len=%u"), (unsigned)cemi_len);
    return false;
  }
  KnxTnlTxQ[KnxTnlTxQTail].len = cemi_len;
  memcpy(KnxTnlTxQ[KnxTnlTxQTail].cemi, cemi, cemi_len);
  KnxTnlTxQTail = (uint8_t)((KnxTnlTxQTail + 1) % KNX_TNL_TXQ_LEN);
  KnxTnlTxQCount++;
  return true;
}

static void KnxTunnelTxBuildAndSend(uint8_t seq, const uint8_t *cemi, uint16_t cemi_len) {
  // Build KNXnet/IP TUNNELING_REQUEST with standard connection header (0x04 length byte)
  uint16_t total = (uint16_t)(6 + 4 + cemi_len);
  if (total > sizeof(KnxTnlTxInFlight.pkt)) { return; }

  uint8_t *pkt = KnxTnlTxInFlight.pkt;
  pkt[0]=0x06; pkt[1]=0x10; pkt[2]=0x04; pkt[3]=0x20; // TUNNELING_REQUEST
  pkt[4]=(uint8_t)(total>>8); pkt[5]=(uint8_t)(total & 0xFF);
  pkt[6]=0x04;            // connection header length
  pkt[7]=KnxTnlChannel;   // channel
  pkt[8]=seq;             // sequence
  pkt[9]=0x00;            // reserved
  memcpy(&pkt[10], cemi, cemi_len);

  KnxTnlTxInFlight.pkt_len = total;
  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvDataPort, pkt, total);
  KnxTnlStatTxReq++;
}

static void KnxTunnelTxTick(void) {
  if (!KnxTunnelConnected()) { return; }
  uint32_t now = millis();

  if (KnxTnlTxInFlight.active) {
    if ((now - KnxTnlTxInFlight.sent_ms) > KNX_TNL_TX_ACK_TIMEOUT_MS) {
      if (KnxTnlTxInFlight.tries >= KNX_TNL_TX_MAX_RETRIES) {
        AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel TX failed (no ACK) seq=%u"), KnxTnlTxInFlight.seq);
        KnxTnlStatTxDrop++;
        KnxTnlTxInFlight.active = false;
        KnxTnlTxInFlight.pkt_len = 0;
        KnxTnlTxInFlight.tries = 0;
        KnxTnlTxInFlight.sent_ms = 0;
      } else {
        KnxTnlTxInFlight.tries++;
        KnxTnlTxInFlight.sent_ms = now;
        // retransmit exact same packet
        KnxTnlStatTxRetry++;
        KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvDataPort, KnxTnlTxInFlight.pkt, KnxTnlTxInFlight.pkt_len);
      }
    }
    return;
  }

  if (KnxTnlTxQCount == 0) { return; }

  // Dequeue next cEMI and send with current TxNextSeq. Do NOT increment until ACK OK.
  uint16_t cemi_len = KnxTnlTxQ[KnxTnlTxQHead].len;
  const uint8_t *cemi = KnxTnlTxQ[KnxTnlTxQHead].cemi;
  KnxTnlTxQHead = (uint8_t)((KnxTnlTxQHead + 1) % KNX_TNL_TXQ_LEN);
  KnxTnlTxQCount--;

  KnxTnlTxInFlight.active = true;
  KnxTnlTxInFlight.seq = KnxTnlTxNextSeq;
  KnxTnlTxInFlight.tries = 1;
  KnxTnlTxInFlight.sent_ms = now;

  KnxTunnelTxBuildAndSend(KnxTnlTxInFlight.seq, cemi, cemi_len);
}

static void KnxTunnelTxHandleAck(uint8_t ch, uint8_t seq, uint8_t status) {
  if (!KnxTunnelConnected() || (ch != KnxTnlChannel)) { return; }
  uint32_t now = millis();
  KnxTnlLastRxMs = now;
  KnxTnlLastCommMs = now;

  if (!KnxTnlTxInFlight.active || (seq != KnxTnlTxInFlight.seq)) {
    // Ignore ACKs not matching our inflight telegram
    return;
  }

  if (status == 0x00) {
    // ACK OK => advance sequence and clear inflight
    KnxTnlStatTxAckOk++;
    KnxTnlTxNextSeq = (uint8_t)((KnxTnlTxNextSeq + 1) & 0xFF);
    KnxTnlTxInFlight.active = false;
    KnxTnlTxInFlight.pkt_len = 0;
    KnxTnlTxInFlight.tries = 0;
    KnxTnlTxInFlight.sent_ms = 0;

    // Immediately send next queued telegram if any
    KnxTunnelTxTick();
  } else {
    AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel TX ACK error status=0x%02X seq=%u"), status, seq);
    KnxTnlStatTxAckErr++;
    // Keep inflight; retry logic will handle.
    KnxTnlTxInFlight.sent_ms = millis();
  }
}

static bool KnxTunnelSendCemi(const uint8_t *cemi, uint16_t cemi_len, uint8_t &seq_used) {
  seq_used = 0;
  if (!KnxTunnelTxEnqueue(cemi, cemi_len)) { return false; }
  // Try to send immediately (non-blocking stop-and-wait)
  KnxTunnelTxTick();
  return true;
}

static void KnxTunnelBuildCemiDpt1(uint16_t ga, uint8_t apci /*0=read,1=response,2=write*/, uint8_t value,
                                   uint8_t *out, uint16_t &out_len) {
  // cEMI L_Data.req (common EMI)
  // 11 00 BC E0 srcHi srcLo dstHi dstLo npduLen tpci_apci0 tpci_apci1
  out[0]=0x11; out[1]=0x00; out[2]=0xBC; out[3]=0xE0;

  uint16_t src = Settings->knx_physsical_addr; // always use configured IA (match PowerShell tunnel test)
  // NOTE: Tasmota stores IA/GA as little-endian 16-bit; KNXnet/IP cEMI uses big-endian bytes.
  out[4]=(uint8_t)(src & 0xFF); out[5]=(uint8_t)(src>>8);
  out[6]=(uint8_t)(ga & 0xFF);  out[7]=(uint8_t)(ga>>8);

  // TPDU is always 2 bytes for GroupValueRead/Response/Write on DPT1
  out[8] = 0x01; // TPDU length (2) - 1

  // Encode APCI into TPDU per KNX spec:
  // apci is 4 bits: hi2 -> tpdu0 bits1..0, lo2 -> tpdu1 bits7..6.
  uint8_t apciHi2 = (uint8_t)((apci >> 2) & 0x03);
  uint8_t apciLo2 = (uint8_t)(apci & 0x03);

  out[9]  = apciHi2; // TPCI=0 + APCI high bits
  out[10] = (uint8_t)((apciLo2 << 6) | (value ? 0x01 : 0x00));

  out_len = 11;
}

bool KnxTunnelSendDpt1Write(uint16_t ga, uint8_t value) {
  uint8_t cemi[16]; uint16_t cemi_len = 0; uint8_t seq = 0;
  KnxTunnelBuildCemiDpt1(ga, 2, value, cemi, cemi_len);
  return KnxTunnelSendCemi(cemi, cemi_len, seq);
}

bool KnxTunnelSendGroupValueRead(uint16_t ga) {
  if (!KnxTunnelConnected()) { return false; }
  uint8_t cemi[16]; uint16_t cemi_len = 0; uint8_t seq = 0;
  // GroupValue_Read has no payload; DPT is irrelevant at this layer.
  KnxTunnelBuildCemiDpt1(ga, 0, 0, cemi, cemi_len);
  return KnxTunnelSendCemi(cemi, cemi_len, seq);
}


static void KnxTunnelBuildCemiGroupApdu(uint16_t ga, uint8_t apci /*0=read,1=response,2=write*/,
                                          const uint8_t *data, uint8_t data_len,
                                          uint8_t *out, uint16_t &out_len) {
  // Generic cEMI L_Data.req for group address with standard TPDU/APCI encoding.
  // Layout:
  //  11 00 BC E0 srcHi srcLo dstHi dstLo npduLen tpci_apci0 tpci_apci1 [data...]
  out[0]=0x11; out[1]=0x00; out[2]=0xBC; out[3]=0xE0;

  uint16_t src = Settings->knx_physsical_addr; // always use configured IA (match PowerShell tunnel test)
  // NOTE: Tasmota stores IA/GA as little-endian 16-bit; KNXnet/IP cEMI uses big-endian bytes.
  out[4]=(uint8_t)(src & 0xFF); out[5]=(uint8_t)(src>>8);
  out[6]=(uint8_t)(ga & 0xFF);  out[7]=(uint8_t)(ga>>8);

  // Encode APCI into TPDU per KNX spec:
  // apci is 4 bits: hi2 -> tpdu0 bits1..0, lo2 -> tpdu1 bits7..6.
  uint8_t apciHi2 = (uint8_t)((apci >> 2) & 0x03);
  uint8_t apciLo2 = (uint8_t)(apci & 0x03);

  // Default: do not embed payload into tpdu1 low bits except for DPT1-style boolean.
  uint8_t val6 = 0x00;
  bool embed_dpt1 = false;
  if ((data_len == 1) && ((data[0] == 0x00) || (data[0] == 0x01))) {
    embed_dpt1 = true;
    val6 = (uint8_t)(data[0] & 0x01);
  }

  out[9]  = apciHi2;                       // TPCI=0 + APCI high bits
  out[10] = (uint8_t)((apciLo2 << 6) | val6);

  if (apci == 0) {
    // GroupValueRead has no payload
    out[8] = 0x01;   // TPDU length (2) - 1
    out_len = 11;
    return;
  }

  if (embed_dpt1) {
    // Boolean encoded in tpdu1 bit0; no extra data bytes
    out[8] = 0x01;   // TPDU length (2) - 1
    out_len = 11;
    return;
  }

  // For all other payloads, data bytes follow after tpdu1.
  // NPDU len = (TPDU bytes (2 + data_len)) - 1 = data_len + 1
  out[8] = (uint8_t)(data_len + 1);
  for (uint8_t i = 0; i < data_len; i++) {
    out[11 + i] = data[i];
  }
  out_len = (uint16_t)(11 + data_len);
}

static void KnxTunnelBuildCemiGroupWrite(uint16_t ga, const uint8_t *data, uint8_t data_len, uint8_t *out, uint16_t &out_len) {
  // GroupValueWrite APCI = 2
  KnxTunnelBuildCemiGroupApdu(ga, 2, data, data_len, out, out_len);
}

// Build a cEMI L_Data.req for GroupValue_Response (APCI=GroupValueResponse, apci=1)
static void KnxTunnelBuildCemiGroupResponse(uint16_t dst_ga, const uint8_t* data, uint8_t data_len,
                                            uint8_t* out, uint16_t &out_len) {
  KnxTunnelBuildCemiGroupApdu(dst_ga, 1, data, data_len, out, out_len);
}

static bool KnxTunnelSendGroupResponse(uint16_t dst_ga, const uint8_t* data, uint8_t data_len) {
  if (!KnxTunnelConnected()) { return false; }
  uint8_t cemi[64];
  uint16_t cemi_len = 0;
	KnxTunnelBuildCemiGroupResponse(dst_ga, data, data_len, cemi, cemi_len);
	uint8_t seq = 0;
	return KnxTunnelSendCemi(cemi, cemi_len, seq);
}


static bool KnxTunnelSendGroupWrite(uint16_t ga, const uint8_t *data, uint8_t data_len) {
  uint8_t cemi[32]; uint16_t cemi_len = 0; uint8_t seq = 0;
  if (data_len > 16) { return false; }
  KnxTunnelBuildCemiGroupWrite(ga, data, data_len, cemi, cemi_len);
  return KnxTunnelSendCemi(cemi, cemi_len, seq);
}

static void KnxTunnelEncodeDpt9(float value, uint8_t out[2]) {
  // KNX 2-byte float (DPT9): 1 sign, 4 exp, 11 mantissa, value = 0.01 * mantissa * 2^exp
  // Range approx -671088.64 .. 670760.96
  bool neg = (value < 0);
  float v = neg ? -value : value;

  // scale to centi-units
  int32_t mant = (int32_t)lroundf(v * 100.0f);
  int8_t exp = 0;

  // fit mantissa into 11 bits signed (-2048..2047)
  while (mant > 2047 && exp < 15) {
    mant >>= 1;
    exp++;
  }

  if (mant > 2047) { mant = 2047; }
  if (neg) { mant = -mant; }

  uint16_t raw = 0;
  raw |= (uint16_t)((neg ? 1 : 0) << 15);
  raw |= (uint16_t)((exp & 0x0F) << 11);
  raw |= (uint16_t)(mant & 0x07FF);

  out[0] = (uint8_t)(raw >> 8);
  out[1] = (uint8_t)(raw & 0xFF);
}

bool KnxTunnelSendDpt5Write(uint16_t ga, uint8_t value) {
  return KnxTunnelSendGroupWrite(ga, &value, 1);
}

bool KnxTunnelSendDpt5Response(uint16_t ga, uint8_t value) {
  return KnxTunnelSendGroupResponse(ga, &value, 1);
}

bool KnxTunnelSendDpt9Write(uint16_t ga, float value) {
  uint8_t data[2];
  KnxTunnelEncodeDpt9(value, data);
  return KnxTunnelSendGroupWrite(ga, data, 2);
}

bool KnxTunnelSendDpt9Response(uint16_t ga, float value) {
  uint8_t data[2];
  KnxTunnelEncodeDpt9(value, data);
  return KnxTunnelSendGroupResponse(ga, data, 2);
}

bool KnxTunnelSendDpt14Write(uint16_t ga, float value) {
  union { float f; uint32_t u; } cvt;
  cvt.f = value;
  uint8_t data[4];
  data[0] = (uint8_t)(cvt.u >> 24);
  data[1] = (uint8_t)(cvt.u >> 16);
  data[2] = (uint8_t)(cvt.u >> 8);
  data[3] = (uint8_t)(cvt.u & 0xFF);
  return KnxTunnelSendGroupWrite(ga, data, 4);
}

bool KnxTunnelSendDpt14Response(uint16_t ga, float value) {
  union { float f; uint32_t u; } cvt;
  cvt.f = value;
  uint8_t data[4];
  data[0] = (uint8_t)(cvt.u >> 24);
  data[1] = (uint8_t)(cvt.u >> 16);
  data[2] = (uint8_t)(cvt.u >> 8);
  data[3] = (uint8_t)(cvt.u & 0xFF);
  return KnxTunnelSendGroupResponse(ga, data, 4);
}


static bool KnxTunnelSendDpt1Read(uint16_t ga) {
  uint8_t cemi[16]; uint16_t cemi_len = 0; uint8_t seq = 0;
  KnxTunnelBuildCemiDpt1(ga, 0, 0, cemi, cemi_len);
  return KnxTunnelSendCemi(cemi, cemi_len, seq);
}

static bool KnxTunnelSendDpt1Response(uint16_t ga, uint8_t value) {
  uint8_t cemi[16]; uint16_t cemi_len = 0; uint8_t seq = 0;
  KnxTunnelBuildCemiDpt1(ga, 1, value, cemi, cemi_len);
  return KnxTunnelSendCemi(cemi, cemi_len, seq);
}

static void KnxTunnelRxDpt1(uint16_t dst_ga, uint8_t value, uint8_t apci) {
  // Map via existing callback table (CB) used by esp-knx-ip integration.
  // apci: 0=read,1=response,2=write
  if (!Settings->flag.knx_enabled) { return; }


  // --- Feedback GA handling (GA table: Data to Send to Group Addresses) ---
  // Treat feedback GAs as read-only for writes from the bus, but answer reads.
  // This allows ETS GroupValue_Read on the feedback GA (e.g. 1/1/4) to be answered
  // without requiring the GA to be added to the CB/RX table.
  const uint16_t dst_sw = (uint16_t)((dst_ga >> 8) | (dst_ga << 8));
  for (uint32_t gi = 0; gi < Settings->knx_GA_registered; gi++) {
    const uint16_t ga  = Settings->knx_GA_addr[gi];
    const uint8_t  dev = Settings->knx_GA_param[gi];  // 1..8 (Output 1..)
    if ((ga == 0) || (dev == 0)) { continue; }
    if ((ga != dst_ga) && (ga != dst_sw)) { continue; }

    // Incoming WRITE to feedback GA is ignored (feedback-only).
    if (apci == 2) {
      return;
    }

    // Incoming READ to feedback GA: answer with current relay state.
    if (apci == 0) {
      if ((dev >= 1) && (dev <= 8)) {
        const uint8_t st = (uint8_t)bitRead(TasmotaGlobal.power, dev - 1);
        // Use tunnelling response directly to keep behaviour independent from CB table.
        KnxTunnelSendDpt1Response((uint16_t)ga, st ? 1 : 0);
      }
      return;
    }

    // Response addressed to feedback GA: ignore.
    return;
  }

  for (uint32_t i = 0; i < Settings->knx_CB_registered; i++) {
    const uint16_t cb = Settings->knx_CB_addr[i];
    // Be tolerant to endian differences between stored settings and cEMI payload.
    if ((cb != dst_ga) && (cb != dst_sw)) { continue; }

    uint8_t j = Settings->knx_CB_param[i];       // 1-based index into device_param[]
    if ((j == 0) || (j > (sizeof(device_param)/sizeof(device_param[0])))) { return; }

    device_parameters_t *chan = &device_param[j - 1];

    // We only transport a 1-bit payload here (DPT1). For "set relay" and "toggle relay" this is correct.
    // For reads (apci==0) we answer based on the mapped channel type so ETS / wall panels can interrogate state.
    address_t receiver;
    receiver.value = cb;

    // --- Incoming WRITE / RESPONSE from the KNX bus ---
    if (apci == 2 || apci == 1) {
      // apci==2: command write from gateway/bus
      // apci==1: response to our reads (used for state sync)
      if (chan->type < 9) {   // Set Relays 1..8
        ExecuteCommandPower(chan->type, value ? POWER_ON : POWER_OFF, SRC_KNX);
        chan->last_state = value ? 1 : 0;
      } else if (chan->type < 17) {  // Toggle Relays 1..8 (type 9..16)
        if (apci == 2) { // Only toggle on explicit writes
          if (!Knx.toggle_inhibit && value) {
            ExecuteCommandPower(chan->type - 8, POWER_TOGGLE, SRC_KNX);
            if (Settings->flag.knx_enable_enhancement) { Knx.toggle_inhibit = TOGGLE_INHIBIT_TIME; }
          }
        } else {
          // Response: treat as absolute state for the underlying relay
          ExecuteCommandPower(chan->type - 8, value ? POWER_ON : POWER_OFF, SRC_KNX);
        }
      }
      return;
    }

    // --- Incoming READ (GroupValue_Read) ---
    if (apci == 0) {
      if (chan->type < 9) {  // reply Relays status (1..8)
        const uint8_t st = (uint8_t)bitRead(TasmotaGlobal.power, chan->type - 1);
        KNX_Send_1bit(receiver, st, KNX_CT_ANSWER);
      } else if (chan->type < 17) { // reply Toggle Relays status
        const uint8_t relay = (uint8_t)(chan->type - 8);
        const uint8_t st = (uint8_t)bitRead(TasmotaGlobal.power, relay - 1);
        KNX_Send_1bit(receiver, st, KNX_CT_ANSWER);
      } else if (chan->type == KNX_TEMPERATURE) {
        #ifdef KNX_USE_DPT9
          KNX_ANSWER_2BYTE_FLOAT(receiver, Knx.last_temp);
        #else
          KNX_ANSWER_4BYTE_FLOAT(receiver, Knx.last_temp);
        #endif
      } else if (chan->type == KNX_HUMIDITY) {
        #ifdef KNX_USE_DPT9
          KNX_ANSWER_2BYTE_FLOAT(receiver, Knx.last_hum);
        #else
          KNX_ANSWER_4BYTE_FLOAT(receiver, Knx.last_hum);
        #endif
      }
#if defined(USE_ENERGY_SENSOR)
      else if (chan->type == KNX_ENERGY_VOLTAGE) {
        KNX_ANSWER_4BYTE_FLOAT(receiver, Energy->voltage[0]);
      } else if (chan->type == KNX_ENERGY_CURRENT) {
        KNX_ANSWER_4BYTE_FLOAT(receiver, Energy->current[0]);
      } else if (chan->type == KNX_ENERGY_POWER) {
        KNX_ANSWER_4BYTE_FLOAT(receiver, Energy->active_power[0]);
      } else if (chan->type == KNX_ENERGY_POWERFACTOR) {
        KNX_ANSWER_4BYTE_FLOAT(receiver, Energy->power_factor[0]);
      } else if (chan->type == KNX_ENERGY_YESTERDAY) {
        KNX_ANSWER_4BYTE_INT(receiver, round(1000.0 * Energy->yesterday_sum));
      } else if (chan->type == KNX_ENERGY_DAILY) {
        KNX_ANSWER_4BYTE_INT(receiver, round(1000.0 * Energy->daily_sum));
      } else if (chan->type == KNX_ENERGY_TOTAL) {
        KNX_ANSWER_4BYTE_INT(receiver, round(1000.0 * Energy->total_sum));
      }
#endif
      return;
    }

    // Unknown/unsupported APCI
    return;
  }
  // No CB match for this destination GA
  // No matching CB/GA mapping for this group telegram; ignore silently.
}


static void KnxTunnelProcessTunnellingRequest(const uint8_t *buf, uint16_t len) {
  // Need at least KNXnet/IP header (6) + connection header (4) + minimal cEMI (11)
  if (len < 6 + 4 + 11) { return; }

  // Connection header (4 bytes) starts at offset 6:
  //  [6]=0x04 length, [7]=channel, [8]=seq, [9]=reserved
  if (buf[6] != 0x04) { return; }
  uint8_t ch  = buf[7];
  uint8_t seq = buf[8];

  // Always ACK the tunneling request with the channel id from the packet
  KnxTunnelSendTunnellingAck(ch, seq);

  // Only process when connected and channel matches
  if (!KnxTunnelConnected() || (ch != KnxTnlChannel)) {
    return;
  }

  // Any valid TUNNELLING_REQUEST for our channel counts as comm (even if duplicate)
  uint32_t now = millis();
  KnxTnlLastRxMs = now;
  KnxTnlLastCommMs = now;

  // Deduplicate on seq to avoid double-apply if retransmitted
  if (seq == KnxTnlSeqRxLast) { return; }
  KnxTnlSeqRxLast = seq;

  const uint8_t *cemi = &buf[10];
  uint16_t cemi_len = (len > 10) ? (uint16_t)(len - 10) : 0;
  if (cemi_len < 11) { return; }

  // Accept L_Data.ind (0x29) / L_Data.con (0x2E) / L_Data.req (0x11)
  uint8_t msg_code = cemi[0];
  if (!(msg_code == 0x29 || msg_code == 0x2E || msg_code == 0x11)) { return; }

  // Additional info length after byte 1
  uint8_t addl = cemi[1];
  uint16_t i = (uint16_t)(2 + addl);
  if (cemi_len < (uint16_t)(i + 9)) { return; }

  uint8_t ctrl2 = cemi[i + 1];
  // Only handle group-addressed telegrams (ctrl2 bit7 = 1)
  if ((ctrl2 & 0x80) == 0) { return; }

  uint16_t dst_be = ((uint16_t)cemi[i + 4] << 8) | cemi[i + 5];

  // Tasmota stores KNX addresses little-endian internally (e.g. 1.1.36 as 0x2411),
  // while cEMI transports them big-endian. Convert to internal representation for CB/GA lookup.
  uint16_t dst = (uint16_t)((dst_be >> 8) | (dst_be << 8));

  // APDU bytes (TPCI/APCI + APCI/data)
  uint8_t apdu0 = cemi[i + 7];
  uint8_t apdu1 = cemi[i + 8];

  uint8_t apci = (uint8_t)(((apdu0 & 0x03) << 2) | ((apdu1 & 0xC0) >> 6));  // 0..15
  uint8_t val  = (uint8_t)(apdu1 & 0x01);

  if (apci <= 2) {
    KnxTunnelRxDpt1(dst, val, apci);
  }
}

static void KnxTunnelSendDisconnectRequest(uint8_t ch) {
  // Best-effort disconnect (no response required). Safe to call in error paths.
  if (!ch) { return; }
  uint8_t buf[16] = {0};
  // KNXnet/IP header
  buf[0] = 0x06; buf[1] = 0x10;
  // DISCONNECT_REQUEST
  buf[2] = 0x02; buf[3] = 0x09;
  // total length
  buf[4] = 0x00; buf[5] = 0x10;
  // channel id + reserved
  buf[6] = ch; buf[7] = 0x00;
  // control endpoint HPAI (UDP, address=0.0.0.0, port=0) -> gateway uses source endpoint
  buf[8]  = 0x08; buf[9]  = 0x01;
  buf[10] = 0x00; buf[11] = 0x00; buf[12] = 0x00; buf[13] = 0x00;
  buf[14] = 0x00; buf[15] = 0x00;

  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvCtrlPort, buf, sizeof(buf));
}


static void KnxTunnelSendDisconnectResponse(uint8_t ch, uint8_t status) {
  if (!ch) { return; }
  uint8_t buf[8] = {0};
  buf[0] = 0x06; buf[1] = 0x10;
  buf[2] = 0x02; buf[3] = 0x0A; // DISCONNECT_RESPONSE
  buf[4] = 0x00; buf[5] = 0x08;
  buf[6] = ch;
  buf[7] = status; // 0x00 OK
  // Send to server control endpoint
  KnxTunnelSendRawTo(KnxTnlGwIp, KnxTnlSrvCtrlPort, buf, sizeof(buf));
}

void KnxTunnelDisconnectNow(void) {
  // Best-effort disconnect on reboot/OTA to free gateway tunnel slot quickly.
  if (KnxTunnelConnected()) {
    KnxTunnelSendDisconnectRequest(KnxTnlChannel);
    // Locally reset channel state; connection will be re-established after reboot anyway.
    KnxTnlChannel = 0;
  }
}




static void KnxTunnelProcessPacket(const uint8_t *buf, uint16_t len) {
  if (len < 6) { return; }
  if (buf[0] != 0x06 || buf[1] != 0x10) { return; }
  uint16_t st = ((uint16_t)buf[2] << 8) | buf[3];

  if (st == 0x0206) { // CONNECT_RESPONSE
  if (len < 8) { return; }
  uint8_t ch = buf[6];
  uint8_t status = buf[7];

  KnxTnlConnectPending = false;

  // If already connected, ignore duplicates. If an extra slot was allocated, free it.
  if (KnxTunnelConnected()) {
    if ((status == 0x00) && (ch != KnxTnlChannel) && (ch != 0)) {
      AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Extra tunnel slot allocated ch=%u, releasing"), ch);
      KnxTunnelSendDisconnectRequest(ch);
    }
    return;
  }

  if (status != 0x00) {
    AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel connect refused (status=0x%02X)"), status);
    KnxTnlLastConnTryMs = millis();
    // Keep UDP socket open; just back off before retrying
    return;
  }

  // Learn server endpoints (control/data) from CONNECT_RESPONSE (HPAI structures)
  // Some servers do not use the well-known port for subsequent services.
  KnxTnlSrvCtrlPort = KnxTnlGwPort;
  KnxTnlSrvDataPort = KnxTnlGwPort;
  if (len >= 24) {
    // HPAI control at bytes 8..15, HPAI data at bytes 16..23
    uint16_t p1 = ((uint16_t)buf[14] << 8) | buf[15];
    uint16_t p2 = ((uint16_t)buf[22] << 8) | buf[23];
    if (p1) { KnxTnlSrvCtrlPort = p1; }
    if (p2) { KnxTnlSrvDataPort = p2; }
  }
  AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Tunnel server ports ctrl=%u data=%u"), KnxTnlSrvCtrlPort, KnxTnlSrvDataPort);
  AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel gw=%u.%u.%u.%u ctrl=%u data=%u ch=%u"), KnxTnlGwIp[0], KnxTnlGwIp[1], KnxTnlGwIp[2], KnxTnlGwIp[3], KnxTnlSrvCtrlPort, KnxTnlSrvDataPort, ch);

  KnxTnlChannel = ch;
  KnxTnlSeqTx = 0;
  KnxTnlSeqRxLast = 0xFF;
    uint32_t now = millis();
  KnxTnlLastKeepAliveMs = now;
  KnxTnlLastRxMs = now;
  KnxTnlLastCommMs = now;
  KnxTnlConnectedAtMs = now;
  KnxTnlStatePending = false;
  KnxTnlLastStateReqMs = 0;

// Reset TX stop-and-wait state on each new tunnel connection
KnxTnlTxNextSeq = 0;
KnxTnlTxQHead = KnxTnlTxQTail = KnxTnlTxQCount = 0;
KnxTnlTxInFlight.active = false;
KnxTnlTxInFlight.pkt_len = 0;
KnxTnlTxInFlight.tries = 0;
KnxTnlTxInFlight.sent_ms = 0;

  // 1Home CONNECT_RESPONSE carries assigned IA as the last two bytes (e.g. 0x11FA)
  KnxTnlAssignedIa = 0;
  KnxTnlSrvCtrlPort = KnxTnlGwPort;
  KnxTnlSrvDataPort = KnxTnlGwPort;
  KnxTnlKeepaliveJitterMs = (uint16_t)random(0, 1001);
  if (len >= 20) {
    /* KnxTnlAssignedIa from CONNECT_RESPONSE ignored; use configured IA */
}

  {
  uint16_t ia_raw = Settings->knx_physsical_addr; // stored little-endian in Settings
  uint16_t ia = (uint16_t)((ia_raw >> 8) | (ia_raw << 8)); // to human-readable A.L.D format
  AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel connected ch=%u IA=%u.%u.%u"),
         KnxTnlChannel,
         (ia >> 12) & 0x0F,
         (ia >> 8) & 0x0F,
         ia & 0xFF);
  KnxTnlPublishPending = true;
}
return;
}

  if (st == 0x0208) { // CONNECTIONSTATE_RESPONSE
    KnxTnlStatRxStateResp++;
    // Byte 6: channel id, byte 7: status
    if (len >= 8) {
      uint8_t resp_ch = buf[6];
      uint8_t status  = buf[7];
      AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Tunnel state resp ch=%u status=0x%02X (local ch=%u)"), resp_ch, status, KnxTnlChannel);

      // Any response clears "pending" (we got *something* back)
      KnxTnlStatePending = false;
      KnxTnlLastStateReqMs = 0;

      if (status != 0x00) {
        AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel state not OK (0x%02X)"), status);
        // Best-effort disconnect to free slot quickly
        KnxTunnelSendDisconnectRequest(KnxTnlChannel);
        // Backoff before reconnect to avoid hammering gateway
        KnxTnlNextConnectMs = millis() + 15000;
        // Reset locally; next loop iteration will reconnect
        KnxTunnelReset();
      } else {
        // Successful keepalive: mark tunnel alive
        uint32_t now2 = millis();
        KnxTnlLastKeepAliveMs = now2;
        KnxTnlLastRxMs = now2;
        KnxTnlLastCommMs = now2;
        KnxTnlKeepaliveJitterMs = (uint16_t)random(0, 1001);
      }
    }
    return;
  }
  if (st == 0x0209) { // DISCONNECT_REQUEST (server initiated)
    // Spec: respond and release channel
    if (len >= 8) {
      uint8_t ch = buf[6];
      KnxTunnelSendDisconnectResponse(ch, 0x00);
    }
    KnxTnlStatReconnect++;
    KnxTunnelReset();
    return;
  }


  if (st == 0x0420) { // TUNNELLING_REQUEST
    KnxTnlStatRxTunReq++;
    KnxTunnelProcessTunnellingRequest(buf, len);
    return;
  }

  if (st == 0x0421) { // TUNNELING_ACK
    KnxTnlStatRxTunAck++; // for our sent telegrams
    // Connection header starts at offset 6: len, channel, seq, status
    if (len >= 10 && buf[6] == 0x04) {
    uint8_t ch = buf[7];
    uint8_t seq = buf[8];
    uint8_t status = buf[9];
    // Any ACK for our channel is comm; TxHandleAck will further validate inflight seq
    if (KnxTunnelConnected() && (ch == KnxTnlChannel)) {
      uint32_t now = millis();
      KnxTnlLastRxMs = now;
      KnxTnlLastCommMs = now;
    }
    KnxTunnelTxHandleAck(ch, seq, status);
  }
  return;
}
}

bool KnxTunnelBegin(void) {
  if (!KnxTunnelConfigured()) { return false; }
  if (KnxTunnelConnected()) { return true; }

  
  uint32_t now = millis();
  if (KnxTnlNextConnectMs && (TimeReached(KnxTnlNextConnectMs) == false)) { return false; }
// If a connect is already in flight, don't send another CONNECT_REQUEST yet.
  // Some gateways allocate a new "slot" per request and only release after their timeout.
  if (KnxTnlConnectPending) { return true; }

  // IP-only: KnxTnlGwIp was parsed in KnxTunnelReloadFromSettings()
  KnxTnlGwPort = KnxTnlPort;

  // Start UDP listener on an ephemeral port (gateway will reply to it)
  KnxTnlUdp.stop();
  // ESP32 core doesn't provide WiFiUDP::localPort(), so we must use a deterministic local port
  // and embed it into CONNECT_REQUEST/CONNECTIONSTATE_REQUEST.
  if (!KnxTnlUdp.begin(KnxTnlLocalPort)) {
    if (KnxTnlLocalPort != 50000) { KnxTnlLocalPort = 50000; }
    if (!KnxTnlUdp.begin(KnxTnlLocalPort)) { return false; }
  }

  KnxTnlConnectPending = true;
  KnxTunnelSendConnectRequest();
  KnxTnlLastConnTryMs = millis();
  KnxTnlLastRxMs = millis();
  return true;
}

void KnxTunnelLoop(void) {
  if (!KnxTunnelConfigured()) { return; }
  if (WiFi.status() != WL_CONNECTED) { return; }

  // Receive loop
  int psize = KnxTnlUdp.parsePacket();
  while (psize > 0) {
    uint8_t buf[256];
    int rlen = KnxTnlUdp.read(buf, sizeof(buf));
    if (rlen > 0) {
      KnxTnlLastRxMs = millis();
      KnxTunnelProcessPacket(buf, (uint16_t)rlen);
    }
    psize = KnxTnlUdp.parsePacket();
  }

  // Drive TX stop-and-wait state machine (non-blocking)
  KnxTunnelTxTick();

  KnxTunnelStatsTick();

  uint32_t now = millis();

  // If not connected, manage connect retries with backoff and a "pending" timeout.
  if (!KnxTunnelConnected()) {
    // If a connect is pending but we haven't heard back for a while, allow a retry.
    if (KnxTnlConnectPending && ((now - KnxTnlLastConnTryMs) > KNX_TNL_CONNECT_TIMEOUT_MS)) {
      KnxTnlConnectPending = false;
    }

    if (!KnxTnlConnectPending && ((now - KnxTnlLastConnTryMs) > KNX_TNL_CONNECT_RETRY_MS)) {
      KnxTunnelBegin();
    }
    return;
  }

  // Publish current output states once per successful tunnel connect (feedback write only)
  if (KnxTnlPublishPending && KnxTnlChannel) {
    KnxTnlPublishPending = false;
    for (uint32_t dev = 1; dev <= TasmotaGlobal.devices_present; dev++) {
      KnxUpdatePowerStateEx(dev, TasmotaGlobal.power, true);
    }
  }

  // Keepalive (CONNECTIONSTATE_REQUEST) periodically to avoid idle tunnel timeouts.
  now = millis();
  // Use the timestamp of the *last successful* CONNECTIONSTATE_RESPONSE to schedule the next request.
  if (!KnxTnlStatePending && ((now - KnxTnlLastCommMs) > (KNX_TNL_KEEPALIVE_MS + KnxTnlKeepaliveJitterMs))) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Keepalive due dt=%u ms (thr=%u+j%u)"), (unsigned)(now - KnxTnlLastCommMs), (unsigned)KNX_TNL_KEEPALIVE_MS, (unsigned)KnxTnlKeepaliveJitterMs);
    AddLog(LOG_LEVEL_DEBUG, PSTR("KNX: Tunnel state req ch=%u lp=%u"), KnxTnlChannel, KnxTnlLocalPort);
    KnxTunnelSendConnectionStateRequest();
    KnxTnlStatePending = true;
    KnxTnlLastStateReqMs = now;
  }

  // If the gateway doesn't answer our keepalive within the specified timeout, retry (max 3) then reconnect.
  if (KnxTnlStatePending && ((now - KnxTnlLastStateReqMs) > KNX_TNL_KEEPALIVE_RSP_TIMEOUT_MS)) {
    if (KnxTnlStateRetry < KNX_TNL_KEEPALIVE_MAX_RETRIES) {
      KnxTnlStateRetry++;
      AddLog(LOG_LEVEL_INFO, PSTR("KNX: Keepalive timeout, retry %u/%u"), KnxTnlStateRetry, KNX_TNL_KEEPALIVE_MAX_RETRIES);
      KnxTunnelSendConnectionStateRequest();
      KnxTnlLastStateReqMs = now;
    } else {
      AddLog(LOG_LEVEL_INFO, PSTR("KNX: Keepalive failed, reconnecting"));
      KnxTnlStatReconnect++;
      KnxTunnelReset();
      return;
    }
  }

  // If no traffic for a long time, reset and reconnect.
  // Note: traffic includes both incoming KNX telegrams and gateway responses to keepalives.
  now = millis();
  // Grace period right after connect: avoid false positives on slow gateways
  if (KnxTnlConnectedAtMs && ((now - KnxTnlConnectedAtMs) < KNX_TNL_CONNECT_GRACE_MS)) {
    return;
  }
  if ((now - KnxTnlLastCommMs) > KNX_TNL_RX_TIMEOUT_MS) {
    AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel timeout, reconnecting"));
    KnxTnlStatReconnect++;
    KnxTunnelReset();
  }
}

void KnxTunnelReconnect(void) {
  KnxTunnelReset();
  if (KnxTunnelConfigured()) {
    KnxTunnelBegin();
  }
}

static void KnxTunnelLoadSettings(void) {
  const char* host = KnxTunnelCfgHost();
  uint16_t port = KnxTunnelCfgPort();

  if (host) {
    strlcpy(KnxTnlHost, host, sizeof(KnxTnlHost));
  } else {
    KnxTnlHost[0] = 0;
  }
  KnxTnlPort = port ? port : 3671;

  // IP-only: avoid blocking DNS lookups in WiFiUDP.beginPacket(host,port) / lwIP.
  KnxTnlGwIp = (uint32_t)0;
  if (KnxTnlHost[0]) {
    // Be tolerant to leading/trailing whitespace even if a UI/plugin stores it.
    // (SettingsUpdateText() already trims, but this prevents "silent disable" on pasted values.)
    char tmp[sizeof(KnxTnlHost)];
    strlcpy(tmp, KnxTnlHost, sizeof(tmp));
    // trim in-place
    char *s = tmp;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') { s++; }
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) { e--; }
    *e = 0;
    strlcpy(KnxTnlHost, s, sizeof(KnxTnlHost));

    IPAddress ip;
    if (!ip.fromString(KnxTnlHost)) {
      AddLog(LOG_LEVEL_INFO, PSTR("KNX: Tunnel disabled (host not a literal IP: '%s')"), KnxTnlHost);
      KnxTnlHost[0] = 0;
    } else {
      KnxTnlGwIp = ip;
    }
  }
}

void KnxTunnelReloadFromSettings(void) {
  KnxTunnelLoadSettings();
  // Only reconnect when the network stack is up. Otherwise, we just reset and let FUNC_NETWORK_UP connect.
  if ((WiFi.status() == WL_CONNECTED) && (!TasmotaGlobal.global_state.network_down)) {
    KnxTunnelReconnect();
  } else {
    KnxTunnelReset();
  }
}


#endif  // USE_KNX