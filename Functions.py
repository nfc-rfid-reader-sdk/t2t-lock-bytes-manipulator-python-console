from ctypes import *
import sys
import array
import ErrorCodes
import time
from t2t_lock_bytes_main import uFR
#################################################################

READER_CONTROLS_AFFECTED        = 0x010000000000
ULTRALIGHT_CONTROLS_AFFECTED    = 0x020000000000
NTAG203_CONTROLS_AFFECTED       = 0x040000000000
NTAG215_CONTROLS_AFFECTED       = 0x400000000000
NTAG216_CONTROLS_AFFECTED       = 0x800000000000
TAG_CONTROLS_AFFECTED           = 0xFE0000000000
ALL_CONTROLS_AFFECTED           = 0xFF0000000000



#################################################################
DLOGIC_CARD_TYPE = {
    'DL_NO_CARD': 0x00,
    'DL_MIFARE_ULTRALIGHT': 0x01,
    'DL_MIFARE_ULTRALIGHT_EV1_11': 0x02,
    'DL_MIFARE_ULTRALIGHT_EV1_21': 0x03,
    'DL_MIFARE_ULTRALIGHT_C': 0x04,
    'DL_NTAG_203': 0x05,
    'DL_NTAG_210': 0x06,
    'DL_NTAG_212': 0x07,
    'DL_NTAG_213': 0x08,
    'DL_NTAG_215': 0x09,
    'DL_NTAG_216': 0x0A,
    'DL_MIKRON_MIK640D': 0x0B,
    'NFC_T2T_GENERIC': 0x0C,
    'DL_NT3H_1101': 0x0D,
    'DL_NT3H_1201': 0x0E,
    'DL_NT3H_2111': 0x0F,
    'DL_NT3H_2211': 0x10,

    'DL_MIFARE_MINI': 0x20,
    'DL_MIFARE_CLASSIC_1K': 0x21,
    'DL_MIFARE_CLASSIC_4K': 0x22,
    'DL_MIFARE_PLUS_S_2K_SL0': 0x23,
    'DL_MIFARE_PLUS_S_4K_SL0': 0x24,
    'DL_MIFARE_PLUS_X_2K_SL0': 0x25,
    'DL_MIFARE_PLUS_X_4K_SL0': 0x26,
    'DL_MIFARE_DESFIRE': 0x27,
    'DL_MIFARE_DESFIRE_EV1_2K': 0x28,
    'DL_MIFARE_DESFIRE_EV1_4K': 0x29,
    'DL_MIFARE_DESFIRE_EV1_8K': 0x2A,
    'DL_MIFARE_DESFIRE_EV2_2K': 0x2B,
    'DL_MIFARE_DESFIRE_EV2_4K': 0x2C,
    'DL_MIFARE_DESFIRE_EV2_8K': 0x2D,
    'DL_MIFARE_PLUS_S_2K_SL1': 0x2E,
    'DL_MIFARE_PLUS_X_2K_SL1'	: 0x2F,
    'DL_MIFARE_PLUS_EV1_2K_SL1': 0x30,
    'DL_MIFARE_PLUS_X_2K_SL2': 0x31,
    'DL_MIFARE_PLUS_S_2K_SL3'	: 0x32,
    'DL_MIFARE_PLUS_X_2K_SL3'	: 0x33,
    'DL_MIFARE_PLUS_EV1_2K_SL3': 0x34,
    'DL_MIFARE_PLUS_S_4K_SL1': 0x35,
    'DL_MIFARE_PLUS_X_4K_SL1'	: 0x36,
    'DL_MIFARE_PLUS_EV1_4K_SL1': 0x37,
    'DL_MIFARE_PLUS_X_4K_SL2'	: 0x38,
    'DL_MIFARE_PLUS_S_4K_SL3'	: 0x39,
    'DL_MIFARE_PLUS_X_4K_SL3'	: 0x3A,
    'DL_MIFARE_PLUS_EV1_4K_SL3': 0x3B,

    # Special card type
    'DL_GENERIC_ISO14443_4': 0x40,
    'DL_GENERIC_ISO14443_4_TYPE_B': 0x41,
    'DL_GENERIC_ISO14443_3_TYPE_B': 0x42,

    'DL_UNKNOWN_ISO_14443_4': 0x40
}

##################################################################


def getCardType():
    cardtype_val = c_ubyte(0)
    getCardTypeFunc = uFR.GetDlogicCardType
    getCardTypeFunc.argtypes = [POINTER(c_ubyte)]
    status = getCardTypeFunc(byref(cardtype_val))
    if status == 0:
        for key, value in DLOGIC_CARD_TYPE.items():
            if cardtype_val.value == value:
                return key, value

##########################################################################

def getCardInformation():

    card_type = c_ubyte(0)
    sak = c_ubyte(0)
    uid = (c_ubyte*10)()
    card_len = c_ubyte(0)
    c = "CARD UID  -> " # string that will be used for printing out UID

    card_type = getCardType()
    if(card_type):
        print("CARD TYPE -> " + str(card_type[0]))
        getCardFunc = uFR.GetCardIdEx
        getCardFunc.argtypes = [POINTER(c_ubyte), (c_ubyte*10), POINTER(c_ubyte)]
        status = getCardFunc(byref(sak), uid, byref(card_len))
        if status == 0:
            for x in range(7):
                c += '%0.2x' % uid[x] + ':'
            print(c.upper()[:-1])
        else:
            print("Getting card info failed.")
            print("Status: " + ErrorCodes.UFCODER_ERROR_CODES[status])

##########################################################################

def readLockBytes():
   
    auth_mode = c_ubyte(0x60)
    page_address = c_ubyte(2)
    page_data = (c_ubyte*16)()
    pk_key = (c_ubyte*6)(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
   
    blockReadFunc = uFR.BlockRead_PK
    blockReadFunc.argtypes = [(c_ubyte*16), c_ubyte, c_ubyte, (c_ubyte*6)]

    card_type = getCardType()
    if (card_type):
        if ( (card_type[0] == "DL_MIFARE_ULTRALIGHT") or (card_type[0] == "DL_MIFARE_ULTRALIGHT_C") or (card_type[0] == "DL_NTAG_203") or (card_type[0] == "DL_NTAG_215") or (card_type[0] == "DL_NTAG_216")):
            status = blockReadFunc(page_data, page_address, auth_mode, pk_key)
            if status != 0:
                print("  NO DATA  ")
                return
            print("\n ----------  Lock bytes for [%s]  ----------\n" %card_type[0])
            print("  Static lock byte  0: 0x%02X" %page_data[2]) 
            print("  Static lock byte  1: 0x%02X" %page_data[3])
        if ( (card_type[0] == "DL_MIFARE_ULTRALIGHT_C") or (card_type[0] == "DL_NTAG_203") or (card_type[0] == "DL_NTAG_215") or (card_type[0] == "DL_NTAG_216")):
            if ((card_type[0] == "DL_NTAG_203") or (card_type[0] == "DL_MIFARE_ULTRALIGHT_C")):
                page_address = 40
            if (card_type[0] == "DL_NTAG_215"):
                page_address = 130
            if (card_type[0] == "DL_NTAG_216"):
                page_address = 226

            page_data = (c_ubyte*16)()
            status = blockReadFunc(page_data, page_address, auth_mode, pk_key)
            if status != 0:
                print("  NO DYNAMIC LOCK PAGE  ")
                return
            print("  Dynamic lock byte 0: 0x%02X" %page_data[0])
            print("  Dynamic lock byte 1: 0x%02X" %page_data[1])
            print("  Dynamic lock byte 2: 0x%02X\n" %page_data[2])
    else:
        print("     Supported card not found in readers field. Please use one of the supported card types for this example:")
        print("     DL_MIFARE_ULTRALIGHT  ||  DL_MIFARE_ULTRALIGHT_C  ||  DL_NTAG_203  || DL_NTAG_215  || DL_NTAG_216")

def writeLockBytes():
    auth_mode = c_ubyte(0x60)
    page_address_static_bytes = c_ubyte(2)
    page_address_dynamic_bytes = c_ubyte(40)
    page_data = (c_ubyte*16)()
    
    pk_key = (c_ubyte*6)(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)

    blockWriteFunc = uFR.BlockWrite_PK
    blockWriteFunc.argtypes = [(c_ubyte*16), c_ubyte, c_ubyte, (c_ubyte*6)]

    blockReadFunc = uFR.BlockRead_PK
    blockReadFunc.argtypes = [(c_ubyte*16), c_ubyte, c_ubyte, (c_ubyte*6)]

    card_type = getCardType()
    if (card_type): #if the card is present
        if ( (card_type[0] == "DL_MIFARE_ULTRALIGHT") or (card_type[0] == "DL_MIFARE_ULTRALIGHT_C") or (card_type[0] == "DL_NTAG_203") or (card_type[0] == "DL_NTAG_215") or (card_type[0] == "DL_NTAG_216")):
            # reading existing data
            status = blockReadFunc(page_data, page_address_static_bytes, auth_mode, pk_key)
            if status != 0:
                print("  NO DATA  ")
                return

            # then we take input as to change lock bytes as we want them
            print("Enter Static lock byte 0: (0x as prefix, e.g 0x70)")
            static_lock_byte_0_str = input()
            if not (static_lock_byte_0_str.startswith("0x")):
                print("invalid input")
                return
            static_lock_byte_0 = c_ubyte(int(static_lock_byte_0_str, 16))
            
            print("Enter Static lock byte 1: (0x as prefix, e.g 0x70)")
            static_lock_byte_1_str = input()
            static_lock_byte_1 = c_ubyte(int(static_lock_byte_1_str, 16))
            if not (static_lock_byte_1_str.startswith("0x")):
                print("invalid input")
                return

            print("Enter Dynamic lock byte 0: (0x as prefix, e.g 0x70)")
            dynamic_lock_byte_0_str = input()
            if not (dynamic_lock_byte_0_str.startswith("0x")):
                print("invalid input")
                return
            dynamic_lock_byte_0 = c_ubyte(int(dynamic_lock_byte_0_str, 16))

            print("Enter Dynamic lock byte 1: (0x as prefix, e.g 0x70)")
            dynamic_lock_byte_1_str = input()
            if not (dynamic_lock_byte_1_str.startswith("0x")):
                print("invalid input")
                return
            dynamic_lock_byte_1 = c_ubyte(int(dynamic_lock_byte_1_str, 16))

            if ((card_type[0] == "DL_NTAG_215") or (card_type[0] == "DL_NTAG_216")):
                print("Enter Dynamic lock byte 2: (0x as prefix, e.g 0x70)")
                dynamic_lock_byte_2_str = input()
                if not (dynamic_lock_byte_2_str.startswith("0x")):
                    print("invalid input")
                    return
                dynamic_lock_byte_2 = c_ubyte(int(dynamic_lock_byte_2_str, 16))

        #write static bytes
        page_data[2] = static_lock_byte_0
        page_data[3] = static_lock_byte_1

        status = blockWriteFunc(page_data, page_address_static_bytes, auth_mode, pk_key)
        if status != 0:
            print("Writing Static lock bytes failed, status: " + ErrorCodes.UFCODER_ERROR_CODES[status])
            return
        #print write dynamic bytes
        if ( (card_type[0] == "DL_NTAG_203") or (card_type[0] == "DL_MIFARE_ULTRALIGHT_C")):
            page_address_dynamic_bytes = c_ubyte(40)
        if (card_type[0] == "DL_NTAG_215"):
            page_address_dynamic_bytes = c_ubyte(130)
        if (card_type[0] == "DL_NTAG_216"):
            page_address_dynamic_bytes = c_ubyte(226)
        
        status = blockReadFunc(page_data, page_address_dynamic_bytes, auth_mode, pk_key)
        if status != 0:
            print("  NO DATA  ")
            return
        
        page_data[0] = dynamic_lock_byte_0
        page_data[1] = dynamic_lock_byte_1
        if (card_type[0] == "DL_NTAG_216"):
            page_data[2] = dynamic_lock_byte_2

        status = blockWriteFunc(page_data, page_address_dynamic_bytes, auth_mode, pk_key)
        if status != 0:
            print("Writing Dynamic lock bytes failed, status: " + ErrorCodes.UFCODER_ERROR_CODES[status])
            return
        
        print("Data has been written!")
    else:
        print("     Supported card not found in readers field. Please use one of the supported card types for this example:")
        print("     DL_MIFARE_ULTRALIGHT  ||  DL_MIFARE_ULTRALIGHT_C  ||  DL_NTAG_203  || DL_NTAG_215  || DL_NTAG_216")


