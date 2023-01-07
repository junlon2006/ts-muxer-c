/**************************************************************************
 * Copyright (C) 2022-2023  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************/
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>

#include "ts_muxer.h"
#include "log.h"

#define TAG                      "[ts_muxer]"

#include <stdio.h>
/**
 * @brief aes128 cbc encrypt start
 * 
 */
#define EASY_AES_KEY_LEN        (16)
#define EASY_AES_BLOCKLEN       (16)
#define Nb                      (4)
#define Nk                      (4)
#define Nr                      (10)
#define EASY_AES_KEY_EXP_SIZE   (176)

typedef uint8_t state_t[4][4];

typedef struct {
  uint8_t roundkey[EASY_AES_KEY_EXP_SIZE];
  uint8_t iv[EASY_AES_BLOCKLEN];
} aes_t;

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// The round constant word array, rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getSBoxValue(num) (sbox[(num)])
// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void __key_expansion(uint8_t* roundkey, const uint8_t* key)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i) {
    roundkey[(i * 4) + 0] = key[(i * 4) + 0];
    roundkey[(i * 4) + 1] = key[(i * 4) + 1];
    roundkey[(i * 4) + 2] = key[(i * 4) + 2];
    roundkey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    k = (i - 1) * 4;
    tempa[0] = roundkey[k + 0];
    tempa[1] = roundkey[k + 1];
    tempa[2] = roundkey[k + 2];
    tempa[3] = roundkey[k + 3];

    if (i % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      const uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = u8tmp;

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);

      tempa[0] = tempa[0] ^ rcon[i/Nk];
    }

    j = i * 4; k= (i - Nk) * 4;
    roundkey[j + 0] = roundkey[k + 0] ^ tempa[0];
    roundkey[j + 1] = roundkey[k + 1] ^ tempa[1];
    roundkey[j + 2] = roundkey[k + 2] ^ tempa[2];
    roundkey[j + 3] = roundkey[k + 3] ^ tempa[3];
  }
}

static void __xor_with_iv(uint8_t* buf, const uint8_t* iv)
{
  uint32_t i;
  for (i = 0; i < EASY_AES_BLOCKLEN; ++i) {// The block in AES is always 128bit no matter the key size
    buf[i] ^= iv[i];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void __add_roundkey(uint8_t round, state_t* state, const uint8_t* roundkey)
{
  uint32_t i,j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[i][j] ^= roundkey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The __sub_bytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void __sub_bytes(state_t* state)
{
  uint32_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The __shift_rows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void __shift_rows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

#define xtime(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// __mix_columns function mixes the columns of the state matrix
static void __mix_columns(state_t* state)
{
  uint32_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i) {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// __cipher is the main function that encrypts the PlainText.
static void __cipher(state_t* state, const uint8_t* roundkey)
{
  uint32_t round = 0;

  // Add the First round key to the state before starting the rounds.
  __add_roundkey(0, state, roundkey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without __mix_columns()
  for (round = 1; ; ++round) {
    __sub_bytes(state);
    __shift_rows(state);
    if (round == Nr) {
      break;
    }
    __mix_columns(state);
    __add_roundkey(round, state, roundkey);
  }
  // Add round key to last round
  __add_roundkey(Nr, state, roundkey);
}

static void __pkcs7_padding(uint8_t *data, size_t *len)
{
  size_t actual_len = *len;
  uint8_t padding_len = 16 - (actual_len & 15);
  uint32_t i;

  for (i = 0; i < padding_len; i++) {
    data[actual_len + i] = padding_len;
  }

  *len += padding_len;
}

static void __easy_aes_cbc_encrypt(const uint8_t iv[EASY_AES_BLOCKLEN],
                                   const uint8_t key[EASY_AES_KEY_LEN],
                                   uint8_t *data, size_t *len)
{
  aes_t aes;
  size_t i;
  uint8_t *iv_ = aes.iv;

  /* step1. initialize */
  __key_expansion(aes.roundkey, key);
  memcpy(aes.iv, iv, EASY_AES_BLOCKLEN);

  /* step2. PKCS#7 padding */
  __pkcs7_padding(data, len);

  /* step3. encrypt */
  for (i = 0; i < *len; i += EASY_AES_BLOCKLEN) {
    __xor_with_iv(data, iv_);
    __cipher((state_t*)data, aes.roundkey);
    iv_ = data;
    data += EASY_AES_BLOCKLEN;
  }
}
/**
 * @brief aes128 cbc encrypt end
 * 
 */

#define TS_PACKET_SIZE           (188)
#define TS_SYNC_BYTE             (0x47)
#define PAT_HEADER_SIZE          (8)
#define TS_PAT_PID               (0x0000)
#define TS_PSI_STREAM_CNT        (2)
#define TS_PMT_HEADER_SIZE       (12)
#define PMT_ELEMENT_SIZE         (5)
#define TS_PACKET_HEADER_SIZE    (4)
#define PTS_FIELD_SIZE           (5)
#define DTS_FIELD_SIZE           (5)
#define PCR_FIELD_SIZE           (6)
#define ADAPT_HEADER_LEN         (2)
#define PES_HEADER_LEN           (9)
#define MAX_PTS                  (1LL << 33)
#define M3U8_BUFFER_SIZE         (512)
#define TS_FILE_NAME_BUF_SIZE    (M3U8_BUFFER_SIZE >> 1)
#define M3U8_ENDLIST_TAG         "#EXT-X-ENDLIST"
#define M3U8_ENDLIST_TAG_LEN     (14)   /* strlen(M3U8_ENDLIST_TAG) */
#define TS_SLICE_BUF_SIZE        (188 * 1024)
#define DEFAULT_PTS              (UINT16_MAX * 90ULL)

/**
 * Macro to set the transport packet PID into a transport packet
 * header.  Note that the casting has been intentionally omitted
 * to make sure that the developer is passing the correct parameters.
 */
#define TSMUX_TS_HEADER_PID_SET(tpHdr, pid) \
    { \
      (tpHdr)->pid_12to8 = ((pid) >> 8) & 0x1F; \
      (tpHdr)->pid_7to0 = (pid) & 0xFF; \
    }

/**
 * @brief The table_id field identifies the content of a Transport Stream PSI section
 *
 * These are the registered ITU H.222.0 | ISO/IEC 13818-1 table_id variants.
 */
typedef enum {
  MPTS_TABLE_ID_PROGRAM_ASSOCIATION               = 0x00,
  MPTS_TABLE_ID_CONDITIONAL_ACCESS                = 0x01,
  MPTS_TABLE_ID_TS_PROGRAM_MAP                    = 0x02,
  MPTS_TABLE_ID_TS_DESCRIPTION                    = 0x03,
  MPTS_TABLE_ID_14496_SCENE_DESCRIPTION           = 0x04,
  MPTS_TABLE_ID_14496_SCENE_OBJECT_DESCRIPTION    = 0x05,
  MPTS_TABLE_ID_METADATA                          = 0x06,
  MPTS_TABLE_ID_IPMP_CONTROL_INFORMATION          = 0x07, // defined in ISO/IEC 13818-11

  /* 0x08 - 0x3F : ITU H.222.0 | ISO/IEC 13818-1 reserved */

  /* 0x40 - 0xFE : User private */

  /* Unset */
  MPTS_TABLE_ID_UNSET                             = 0xFF
} mpts_section_table_id;

/**
 *
 * Program configuration.
 */
typedef struct {
  uint16_t pid_pmt; /*!< Packet ID to be used to store the Program Map Table [PMT]. */
  uint16_t pid_pcr; /*!< Packet ID to be used to store the Program Clock Referene [PCR]. */
  uint16_t pid_num; /*!< Program Number to be used in Program Map Table [PMT]. */
} tsmux_psi_prg_inf_t;

/**
 *
 * Program Association table [PAT] configuration
 */
typedef struct {
  uint16_t total_programs; /*!< Total number of valid programs. */
  tsmux_psi_prg_inf_t* program_info_list; /*!< List of program configurations. */
} tsmux_psi_pat_inf_t;

/**
 * Transport packet header.
 */
typedef struct {
#ifdef BIGENDIAN
  /*Btype 3*/
  uint8_t transport_scrambling_control :2; /* TS Scrambling Control.        */
  uint8_t adaptation_field_control     :2;
  uint8_t continuity_counter           :4; /* Countinuity counter.          */
  /*Btype 2*/
  uint8_t pid_7to0                     :8; /* Program ID, bits 7:0.         */
  /*Btype 1*/
  uint8_t transport_error_indicator    :1; /* TS Error Indicator.           */
  uint8_t payload_unit_start_indicator :1;
  uint8_t transport_priority           :1; /* TS Transport Priority.        */
  uint8_t pid_12to8                    :5; /* Program ID, bits 12:8.        */
  /*Btype 0*/
  uint8_t sync_byte                    :8; /* Synchronization byte.         */
#else
  /*Btype 0*/
  uint8_t sync_byte                    :8; /* Synchronization byte.         */
  /*Btype 1*/
  uint8_t pid_12to8                    :5; /* Program ID, bits 12:8.        */
  uint8_t transport_priority           :1; /* TS Transport Priority.        */
  uint8_t payload_unit_start_indicator :1; /* Payload Unit Start Indicator. */
  uint8_t transport_error_indicator    :1; /* TS Error Indicator.           */
  /*Btype 2*/
  uint8_t pid_7to0                     :8; /* Program ID, bits 7:0.         */
  /*Btype 3*/
  uint8_t continuity_counter           :4; /* Countinuity counter.          */
  uint8_t adaptation_field_control     :2;
  uint8_t transport_scrambling_control :2; /* TS Scrambling Control.        */
#endif
} tsmux_ts_header_t;

/**
 *
 * Header for a Program Association table [PAT]
 * ref MPEG-2 Systems Spec ISO/IEC 13818-1
 */
typedef struct {
#ifdef BIGENDIAN
  /*Btype 7*/
  uint8_t last_section_number      : 8;
  /*Btype 6*/
  uint8_t section_number           : 8;
  /*Btype 5*/
  uint8_t reserved1                : 2;
  uint8_t version_number           : 5;
  uint8_t current_next_indicator   : 1;
  /*Btype 4*/
  uint8_t transport_stream_id_l    : 8;
  /*Btype 3*/
  uint8_t transport_stream_id_h    : 8;
  /*Btype 2*/
  uint8_t section_length0to7       : 8;
  /*Btype 1*/
  uint8_t section_syntax_indicator : 1;
  uint8_t b0                       : 1;
  uint8_t reserved0                : 2;
  uint8_t section_length8to11      : 4;
  /*Btype 0*/
  uint8_t table_id                 : 8;
#else
  /*Btype 0*/
  uint8_t table_id                 : 8;
  /*Btype 1*/
  uint8_t section_length8to11      : 4;
  uint8_t reserved0                : 2;
  uint8_t b0                       : 1;
  uint8_t section_syntax_indicator : 1;
  /*Btype 2*/
  uint8_t section_length0to7       : 8;
  /*Btype 3*/
  uint8_t transport_stream_id_h    : 8;
  /*Btype 4*/
  uint8_t transport_stream_id_l    : 8;
  /*Btype 5*/
  uint8_t current_next_indicator   : 1;
  uint8_t version_number           : 5;
  uint8_t reserved1                : 2;
  /*Btype 6*/
  uint8_t section_number           : 8;
  /*Btype 7*/
  uint8_t last_section_number      : 8;
#endif
} tsmux_pat_header_t;

/**
 *
 * Transport stream flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_TRANSPORT_ERROR_INDICATOR_NO_ERRORS = 0,    /* No errors. */
  MPEG_TS_TRANSPORT_ERROR_INDICATOR_ERRORS = 1        /* Errors in the stream. */
};

/**
 *
 * PSUI (payload_start_unit_indicator) as per "ISO/IEC 13818-1"
 */
enum {
  /**
   * If the stream carries PES, No PES starts in the current packet.
   * If the stream carries PSI, the first byte of the packet payload carries the
   * remaining of a previously started section.
   */
  MPEG_TS_PSUI_UNSET = 0,

  /**
   * If the stream carries PES, a PES starts in the current packet at the beginning of the payload.
   * If the stream carries PSI, the packet carries the first byte of a data section.
   */
  MPEG_TS_PSUI_SET = 1
};

/**
 *
 * Transport stream priority flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_TRANSPORT_PRIORITY_NO_PRIORITY = 0, /* No priority data. */
  MPEG_TS_TRANSPORT_PRIORITY_PRIORITY    = 1  /* Priority data. */
};

/**
 *
 * Scrambling control flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_SCRAMBLING_CTRL_NOT_SCRAMBLED = 0,    /* Stream not scrambled. */
  MPEG_TS_SCRAMBLING_CTRL_1             = 0x01, /* User defined. */
  MPEG_TS_SCRAMBLING_CTRL_2             = 0x02, /* User defined. */
  MPEG_TS_SCRAMBLING_CTRL_3             = 0x03  /* User defined. */
};

/**
 *
 * Adaptation field flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_ADAPTATION_FIELD_RESERVED        = 0x00,  /* Reserved for future use by ISO/IEC. */
  MPEG_TS_ADAPTATION_FIELD_PAYLOAD_ONLY    = 0x01,  /* No adaptation field, payload only. */
  MPEG_TS_ADAPTATION_FIELD_ADAPTATION_ONLY = 0x02,  /* Adaptation field only, no payload. */
  MPEG_TS_ADAPTATION_FIELD_BOTH            = 0x03   /* Adaptation field followed by payload. */
};

/**
 *
 * MPEG stream TYPEs as per "ISO/IEC 13818-1"
 * note that stream_type is DIFFERENT from stream_id:
 * stream_type is defined in PMT Program element loop and belongs to Transport Stream layer
 * stream_id is present in PES header and belongs to the PES packet layer
 */
enum {
  MPEG_SI_STREAM_TYPE_RESERVED_0        = 0x00,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_MPEG1_VIDEO       = 0x01,       /* ISO/IEC 11172 Video */
  MPEG_SI_STREAM_TYPE_MPEG2_VIDEO       = 0x02,       /* ITU-T Rec. H.262 | ISO/IEC 13818-2 Video or ISO/IEC 11172 constrained parameter video stream*/
  MPEG_SI_STREAM_TYPE_MPEG1_AUDIO       = 0x03,       /* ISO/IEC 11172 Audio */
  MPEG_SI_STREAM_TYPE_MPEG2_AUDIO       = 0x04,       /* ISO/IEC 13818-3 Audio */
  MPEG_SI_STREAM_TYPE_PRIVATE_SECTION   = 0x05,       /* ITU-T Rec. H.222.0 | ISO/IEC 13818-1 private_sections */
  MPEG_SI_STREAM_TYPE_PRIVATE_PES       = 0x06,       /* ITU-T Rec. H.222.0 | ISO/IEC 13818-1 pes packets containing private data */
  MPEG_SI_STREAM_TYPE_MHEG              = 0x07,       /* ISO/IEC 13522 MHEG */
  MPEG_SI_STREAM_TYPE_DSM_CC            = 0x08,       /* ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC */
  MPEG_SI_STREAM_TYPE_RESERVED_9        = 0x09,       /* ITU-T Rec. H.222.1 */
  MPEG_SI_STREAM_TYPE_RESERVED_10       = 0x0A,       /* ISO/IEC 13818-6 type A */
  MPEG_SI_STREAM_TYPE_RESERVED_11       = 0x0B,       /* ISO/IEC 13818-6 type B */
  MPEG_SI_STREAM_TYPE_RESERVED_12       = 0x0C,       /* ISO/IEC 13818-6 type C */
  MPEG_SI_STREAM_TYPE_RESERVED_13       = 0x0D,       /* ISO/IEC 13818-6 type D */
  MPEG_SI_STREAM_TYPE_RESERVED_14       = 0x0E,       /* ISO/IEC 13818-6 type auxiliary */
  MPEG_SI_STREAM_TYPE_AAC               = 0x0F,       /* ISO/IEC 13818-7 Audio (AAC) */
  MPEG_SI_STREAM_TYPE_MPEG4_AUDIO       = 0x10,       /* MPEG4 Audio elementary stream (MPEG2 PES based) */
  MPEG_SI_STREAM_TYPE_MPEG4_VIDEO       = 0x11,       /* MPEG4 visual elementary stream (MPEG2 PES based) */
  MPEG_SI_STREAM_TYPE_MPEG4_SYSTEM1     = 0x12,       /* MPEG4 SL-packetized stream of FlexMux Stream in MPEG2 PES */
  MPEG_SI_STREAM_TYPE_MPEG4_SYSTEM2     = 0x13,       /* MPEG4 SL-packetized stream of FlexMux Stream ISO/IEC 14496 (MPEG4) */
  MPEG_SI_STREAM_TYPE_RESERVED_20       = 0x14,       /* ISO/IEC 13818-6 DSM-CC Synchronized Download protocol */
  MPEG_SI_STREAM_TYPE_RESERVED_21       = 0x15,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_22       = 0x16,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_23       = 0x17,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_24       = 0x18,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_25       = 0x19,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_26       = 0x1A,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_AVC_VIDEO         = 0x1B,       /* ITU-T Rec. H.264 ISO/IEC 14496-10 Video */
  MPEG_SI_STREAM_TYPE_RESERVED_28       = 0x1C,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_RESERVED_127      = 0x7F,       /* MPEG2 Systems Reserved. */
  MPEG_SI_STREAM_TYPE_LPCM_AUDIO        = 0x80,
  MPEG_SI_STREAM_TYPE_AC3_AUDIO_OR_TTX  = 0x81,
  MPEG_SI_STREAM_TYPE_JPEG              = 0x91,
  MPEG_SI_STREAM_TYPE_G722_16K          = 0x93,
  MPEG_SI_STREAM_TYPE_G722_8K           = 0x94,
  MPEG_SI_STREAM_TYPE_OPUS              = 0x95,
  MPEG_SI_STREAM_TYPE_ALAW              = 0x96,
  MPEG_SI_STREAM_TYPE_MULAW             = 0x97,
};

/**
 *
 * Header for a Program Map Table [PMT]
 * \ref MPEG-2 Systems Spec ISO/IEC 13818-1
 */
typedef struct {
#ifdef BIGENDIAN
  /*Btype 11*/
  uint8_t program_info_length0to7  : 8;
  /*Btype 10*/
  uint8_t reserved3                : 4;
  uint8_t program_info_length8to11 : 4;
  /*Btype 9*/
  uint8_t pcr_pid_0_to_7           : 8;
  /*Btype 8*/
  uint8_t reserved2                : 3;
  uint8_t pcr_pid_8_to_12          : 5;
  /*Btype 7*/
  uint8_t last_section_number      : 8;
  /*Btype 6*/
  uint8_t section_number           : 8;
  /*Btype 5*/
  uint8_t reserved1                : 2;
  uint8_t version_number           : 5;
  uint8_t current_next_indicator   : 1;
  /*Btype 4*/
  uint8_t program_number_l         : 8;
  /*Btype 3*/
  uint8_t program_number_h         : 8;
  /*Btype 2*/
  uint8_t section_length0to7       : 8;
  /*Btype 1*/
  uint8_t section_syntax_indicator : 1;
  uint8_t b0                       : 1;
  uint8_t reserved0                : 2;
  uint8_t section_length8to11      : 4;
  /*Btype 0*/
  uint8_t table_id                 : 8;
#else
  /*Btype 0*/
  uint8_t table_id                 : 8;
  /*Btype 1*/
  uint8_t section_length8to11      : 4;
  uint8_t reserved0                : 2;
  uint8_t b0                       : 1;
  uint8_t section_syntax_indicator : 1;
  /*Btype 2*/
  uint8_t section_length0to7       : 8;
  /*Btype 3*/
  uint8_t program_number_h         : 8;
  /*Btype 4*/
  uint8_t program_number_l         : 8;
  /*Btype 5*/
  uint8_t current_next_indicator   : 1;
  uint8_t version_number           : 5;
  uint8_t reserved1                : 2;
  /*Btype 6*/
  uint8_t section_number           : 8;
  /*Btype 7*/
  uint8_t last_section_number      : 8;
  /*Btype 8*/
  uint8_t pcr_pid_8_to_12          : 5;
  uint8_t reserved2                : 3;
  /*Btype 9*/
  uint8_t pcr_pid_0_to_7           : 8;
  /*Btype 10*/
  uint8_t program_info_length8to11 : 4;
  uint8_t reserved3                : 4;
  /*Btype 11*/
  uint8_t program_info_length0to7  : 8;
#endif
} tsmux_pmt_header_t;

/**
 *
 * Stream configuration
 */
typedef struct {
  uint32_t type; /*!< Program type. */
  uint16_t pid; /*!< Packet ID to be used in the TS. */
  uint8_t descriptor_tag;
  uint32_t descriptor_len;
  uint8_t* descriptor;
} tsmux_psi_stream_inf_t;

/**
 *
 * Program Map Table [PMT] configuration.
 */
typedef struct {
  tsmux_psi_prg_inf_t* program_info_list;
  uint16_t stream_cnt; /*!< Total number of stream within the program. */
  tsmux_psi_stream_inf_t* stream[TS_PSI_STREAM_CNT]; /*!< List of stream configurations. */
  uint8_t descriptor_tag;
  uint32_t descriptor_len;
  uint8_t* descriptor;
} tsmux_psi_pmt_inf_t;

/**
 *
 * Program Map Table [PMT] element
 * \ref MPEG-2 Systems Spec ISO/IEC 13818-1
 */
typedef struct {
#ifdef BIGENDIAN
  /*Btype 4*/
  uint8_t es_info_length_l    : 8;
  /*Btype 3*/
  uint8_t reserved1           : 4;
  uint8_t es_info_length_h    : 4;
  /*Btype 2*/
  uint8_t elementary_pid0to7  : 8;
  /*Btype 1*/
  uint8_t reserved0           : 3;
  uint8_t elementary_pid8to12 : 5;
  /*Btype 0*/
  uint8_t stream_type         : 8;
#else
  /*Btype 0*/
  uint8_t stream_type         : 8;
  /*Btype 1*/
  uint8_t elementary_pid8to12 : 5;
  uint8_t reserved0           : 3;
  /*Btype 2*/
  uint8_t elementary_pid0to7  : 8;
  /*Btype 3*/
  uint8_t es_info_length_h    : 4;
  uint8_t reserved1           : 4;
  /*Btype 4*/
  uint8_t es_info_length_l    : 8;
#endif
} pmt_element_t;

/**
 *
 * MPEG stream IDs as per "ISO/IEC 13818-1"
 * note that stream_id is DIFFERENT from stream_type:
 * stream_id is present in PES header and belongs to the PES packet layer
 * stream_type is defined in PMT Program element loop and belongs to Transport Stream layer
 */
enum {
  MPEG_TS_STREAM_ID_PROGRAM_STREAM_MAP = 0xBC, /* Program stream map. */
  MPEG_TS_STREAM_ID_PRIVATE_STREAM_1   = 0xBD, /* Private stream 1. */
  MPEG_TS_STREAM_ID_PADDING_STREAM     = 0xBE, /* Padding stream. */
  MPEG_TS_STREAM_ID_PRIVATE_STREAM_2   = 0xBF, /* Private stream 2. */
  MPEG_TS_STREAM_ID_AUDIO_00 = 0xC0, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 0. */
  MPEG_TS_STREAM_ID_AUDIO_01 = 0xC1, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 1. */
  MPEG_TS_STREAM_ID_AUDIO_02 = 0xC2, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 2. */
  MPEG_TS_STREAM_ID_AUDIO_03 = 0xC3, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 3. */
  MPEG_TS_STREAM_ID_AUDIO_04 = 0xC4, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 4. */
  MPEG_TS_STREAM_ID_AUDIO_05 = 0xC5, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 5. */
  MPEG_TS_STREAM_ID_AUDIO_06 = 0xC6, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 6. */
  MPEG_TS_STREAM_ID_AUDIO_07 = 0xC7, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 7. */
  MPEG_TS_STREAM_ID_AUDIO_08 = 0xC8, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 8. */
  MPEG_TS_STREAM_ID_AUDIO_09 = 0xC9, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 9. */
  MPEG_TS_STREAM_ID_AUDIO_0A = 0xCA, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 10. */
  MPEG_TS_STREAM_ID_AUDIO_0B = 0xCB, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 11. */
  MPEG_TS_STREAM_ID_AUDIO_0C = 0xCC, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 12. */
  MPEG_TS_STREAM_ID_AUDIO_0D = 0xCD, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 13. */
  MPEG_TS_STREAM_ID_AUDIO_0E = 0xCE, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 14. */
  MPEG_TS_STREAM_ID_AUDIO_0F = 0xCF, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 15. */
  MPEG_TS_STREAM_ID_AUDIO_10 = 0xD0, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 16. */
  MPEG_TS_STREAM_ID_AUDIO_11 = 0xD1, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 17. */
  MPEG_TS_STREAM_ID_AUDIO_12 = 0xD2, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 18. */
  MPEG_TS_STREAM_ID_AUDIO_13 = 0xD3, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 19. */
  MPEG_TS_STREAM_ID_AUDIO_14 = 0xD4, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 20. */
  MPEG_TS_STREAM_ID_AUDIO_15 = 0xD5, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 21. */
  MPEG_TS_STREAM_ID_AUDIO_16 = 0xD6, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 22. */
  MPEG_TS_STREAM_ID_AUDIO_17 = 0xD7, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 23. */
  MPEG_TS_STREAM_ID_AUDIO_18 = 0xD8, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 24. */
  MPEG_TS_STREAM_ID_AUDIO_19 = 0xD9, /* ISO/IEC 13818-3 or ISO11172-3 audio stream number 25. */
  MPEG_TS_STREAM_ID_VIDEO_00 = 0xE0, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 0. */
  MPEG_TS_STREAM_ID_VIDEO_01 = 0xE1, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 1. */
  MPEG_TS_STREAM_ID_VIDEO_02 = 0xE2, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 2. */
  MPEG_TS_STREAM_ID_VIDEO_03 = 0xE3, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 3. */
  MPEG_TS_STREAM_ID_VIDEO_04 = 0xE4, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 4. */
  MPEG_TS_STREAM_ID_VIDEO_05 = 0xE5, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 5. */
  MPEG_TS_STREAM_ID_VIDEO_06 = 0xE6, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 6. */
  MPEG_TS_STREAM_ID_VIDEO_07 = 0xE7, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 7. */
  MPEG_TS_STREAM_ID_VIDEO_08 = 0xE8, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 8. */
  MPEG_TS_STREAM_ID_VIDEO_09 = 0xE9, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 9. */
  MPEG_TS_STREAM_ID_VIDEO_0A = 0xEA, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 10. */
  MPEG_TS_STREAM_ID_VIDEO_0B = 0xEB, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 11. */
  MPEG_TS_STREAM_ID_VIDEO_0C = 0xEC, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 12. */
  MPEG_TS_STREAM_ID_VIDEO_0D = 0xED, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 13. */
  MPEG_TS_STREAM_ID_VIDEO_0E = 0xEE, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 14. */
  MPEG_TS_STREAM_ID_VIDEO_0F = 0xEF, /* ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 video stream 25 number 15. */
  MPEG_TS_STREAM_ID_ECM_STREAM  = 0xF0, /* ECM stream. */
  MPEG_TS_STREAM_ID_EMM_STREAM  = 0xF1, /* EMM stream. */
  MPEG_TS_STREAM_ID_H2220_DSMCC = 0xF2, /* ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A or ISO/IEC 11818-6 DSMCC stream. */
  MPEG_TS_STREAM_ID_ISOIEC_13522 = 0xF3, /* ISO/IEC 13522 stream. */
  MPEG_TS_STREAM_ID_H2221_TYPE_A = 0xF4, /* ITU-T Rec. H.222 type A. */
  MPEG_TS_STREAM_ID_H2221_TYPE_B = 0xF5, /* ITU-T Rec. H.222 type B. */
  MPEG_TS_STREAM_ID_H2221_TYPE_C = 0xF6, /* ITU-T Rec. H.222 type C. */
  MPEG_TS_STREAM_ID_H2221_TYPE_D = 0xF7, /* ITU-T Rec. H.222 type D. */
  MPEG_TS_STREAM_ID_H2221_TYPE_E = 0xF8, /* ITU-T Rec. H.222 type E. */
  MPEG_TS_STREAM_ID_ANCILLARY    = 0xF9, /* Ancillary stream. */
  MPEG_TS_STREAM_ID_RESERVED_00  = 0xFA, /* Reserved data stream. */
  MPEG_TS_STREAM_ID_RESERVED_01  = 0xFB, /* Reserved data stream. */
  MPEG_TS_STREAM_ID_RESERVED_02  = 0xFC, /* Reserved data stream. */
  MPEG_TS_STREAM_ID_RESERVED_03  = 0xFD, /* Reserved data stream. */
  MPEG_TS_STREAM_ID_RESERVED_04  = 0xFE, /* Reserved data stream. */
  MPEG_TS_STREAM_ID_PROGRAM_DIRECTORY = 0xFF, /* Program stream directory. */
};

/**
 *
 * PTS and DTS flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PTS_DTS_NO_PTSDTS   = 0,  /* No PTS or DTS in the stream. */
  MPEG_TS_PTS_DTS_FORBIDDEN   = 1,  /* Forbidden value. */
  MPEG_TS_PTS_DTS_PTS_ONLY    = 2,   /* PTS only in the stream. */
  MPEG_TS_PTS_DTS_PTSDTS_BOTH = 3 /* Both PTS and DTS in the stream. */
};

/**
 *
 * Stream configuration
 */
typedef struct {
  uint8_t first_frame;
  uint8_t first_slice;
  uint8_t with_pcr;
  uint8_t* payload;
  int32_t payload_len;
  uint64_t pts;
  uint64_t dts;
  uint64_t pcr_base;
  uint16_t pcr_ext;
} tsmux_pes_t;

/**
 * Adaptation field header.
 */
typedef struct {
#ifdef BIGENDIAN
  /*Byte 1*/
  uint8_t discontinuity_indicator               :1; /* Discontinuity indicator. */
  uint8_t random_access_indicator               :1; /* Random access indicator. */
  uint8_t elementary_stream_priority_indicator  :1; /* Elementary stream priority indicator. */
  uint8_t pcr_flag                              :1; /* PCR flag. */
  uint8_t opcr_flag                             :1; /* OPCR flag. */
  uint8_t splicing_point_flag                   :1; /* Splicing point flag. */
  uint8_t transport_private_data_flag           :1; /* Transport private data flag. */
  uint8_t adaptation_field_extension_flag       :1; /* Adaptation field extension flag. */
  /*Bype 0*/
  uint8_t adaptation_field_length               :8; /* Adaptation field lenght, this field not included. */
#else
  /*Byte 0*/
  uint8_t adaptation_field_length               :8; /* Adaptation field length, this field not included. */
  /*Byte 1*/
  uint8_t adaptation_field_extension_flag       :1; /* Adaptation field extension flag. */
  uint8_t transport_private_data_flag           :1; /* Transport private data flag. */
  uint8_t splicing_point_flag                   :1; /* Splicing point flag. */
  uint8_t opcr_flag                             :1; /* OPCR flag. */
  uint8_t pcr_flag                              :1; /* PCR flag. */
  uint8_t elementary_stream_priority_indicator  :1; /* Elementary stream priority indicator*/
  uint8_t random_access_indicator               :1; /* Random access indicator. */
  uint8_t discontinuity_indicator               :1; /* Discontinuity indicator. */
#endif
} tsmux_ts_adaptation_t;

/**
 *
 * Transport private data flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_ADAPTATION_FIELD_EXTENSION_NOT_PRESENT = 0, /* There is no adaptation field extension. */
  MPEG_TS_ADAPTATION_FIELD_EXTENSION_PRESENT     = 1  /* It indicates the presence of an adaptation field extension. */
};

/**
 *
 * Transport private data flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_TRANSPORT_PRIVATE_DATA_NOT_PRESENT = 0, /* The adaptation field does not contain one or more private bytes. */
  MPEG_TS_TRANSPORT_PRIVATE_DATA_PRESENT     = 1  /* The adaptation field contains private bytes. */
};

/**
 *
 * Splicing point flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_SPLICING_POINT_FLAG_NOT_PRESENT = 0, /* The adaptation field does not contain a splicing countdown field. */
  MPEG_TS_SPLICING_POINT_FLAG_PRESENT     = 1  /* The adaptation field does contain a splicing countdown field. */
};

/**
 *
 * OPCR flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_OPCR_FLAG_NOT_PRESENT = 0, /* The adaptation field does not contain a OPCR. */
  MPEG_TS_OPCR_FLAG_PRESENT     = 1  /* The adaptation field contains a OPCR. */
};

/**
 *
 * PCR flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PCR_FLAG_NOT_PRESENT = 0, /* The adaptation field does not contain a PCR. */
  MPEG_TS_PCR_FLAG_PRESENT     = 1  /* The adaptation field contains a PCR. */
};

/**
 *
 * Elementary stream priority indicator flags as per "ISO/IEC 13818-1"
 */
enum {
  /** The data carried in this transport
   *  packet doesn't have a higher priority compared with other transport packet with the same PID.
   */
  MPEG_TS_ELEMENTARY_STREAM_PRIORITY_NO_PRIORITY = 0,
  /** The data carried by this transport packet
   *  has higher priority compared with other transport packets with the same PID.
   */
  MPEG_TS_ELEMENTARY_STREAM_PRIORITY_PRIORITY = 1
};

/**
 *
 * Random access indicator flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_RANDOM_ACCESS_INDICATOR_NOT_PRESENT = 0, /* The next data in the stream does not carry information that aids random access. */
  MPEG_TS_RANDOM_ACCESS_INDICATOR_PRESENT     = 1  /* The next data in the stream carries information that aids random access. */
};

/**
 *
 * Discontinuity indicator flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_DISCONTINUITY_INDICATOR_NO_DISCONTINUTY = 0, /* No discontinuity in the stream. */
  MPEG_TS_DISCONTINUITY_INDICATOR_DISCONTINUTY    = 1  /* Discontinuity in the field. */
};

/**
 * PES header.
 */
typedef struct {
#ifdef BIGENDIAN
  /*Byte 9*/
  uint8_t header_data_length       :8; /* Length of optional fields and stuffing bytes. */
  /*Byte 8*/
  uint8_t pts_dts_flags            :2; /* PTS/DTS flag. */
  uint8_t escr_flag                :1; /* ESCR flag. */
  uint8_t es_rate_flag             :1; /* Elementary stream flag. */
  uint8_t dsm_trick_mode_flag      :1; /* DSM trick mode flag. */
  uint8_t add_copy_info_flag       :1; /* Additional copy info flag*/
  uint8_t pes_crc_flag             :1; /* PES CRC flag. */
  uint8_t pes_ext_flag             :1; /* PES extension flag. */
  /*Byte 7*/
  uint8_t marker_bits              :2; /* Marker bits, the should be set to 0x02. */
  uint8_t pes_scrambling_control   :2; /* PES scrambling control. */
  uint8_t pes_priority             :1; /* PES priority. */
  uint8_t data_alignment_indicator :1; /* Data alignment control. */
  uint8_t copyright                :1; /* Copyright flag. */
  uint8_t original_or_copy         :1; /* Original or copy flag. */
  /*Byte 6*/
  uint8_t pes_packet_length_7to0   :8; /* Packet length. Bits 15:8. */
  /*Byte 5*/
  uint8_t pes_packet_length_15to8  :8; /* Packet length. Bits 7:0.  */
  /*Byte 4*/
  uint8_t stream_id                :8; /* Stream ID. */
  /*Byte 3*/
  uint8_t packet_start_code_7to0   :8; /* Packet start code. Bits 7:0. */
  /*Byte 2*/
  uint8_t packet_start_code_15to8  :8; /* Packet start code. Bits 15:8.  */
  /*Byte 1*/
  uint8_t packet_start_code_23to16 :8; /* Packet start code. Bits 23:16.   */
#else
  /*Byte 1*/
  uint8_t packet_start_code_23to16 :8; /* Packet start code. Bits 23:16.   */
  /*Byte 2*/
  uint8_t packet_start_code_15to8  :8; /* Packet start code. Bits 15:8.  */
  /*Byte 3*/
  uint8_t packet_start_code_7to0   :8; /* Packet start code. Bits 7:0. */
  /*Byte 4*/
  uint8_t stream_id                :8; /* Stream ID. */
  /*Byte 5*/
  uint8_t pes_packet_length_15to8  :8; /* Packet length. Bits 15:8. */
  /*Byte 6*/
  uint8_t pes_packet_length_7to0   :8; /* Packet length. Bits 7:0.  */
  /*Byte 7*/
  uint8_t original_or_copy         :1; /* Original or copy flag. */
  uint8_t copyright                :1; /* Copyright flag. */
  uint8_t data_alignment_indicator :1; /* Data alignment control. */
  uint8_t pes_priority             :1; /* PES priority. */
  uint8_t pes_scrambling_control   :2; /* PES scrambling control. */
  uint8_t marker_bits              :2; /* Marker bits, the should be set to 0x02. */
  /*Byte 8*/
  uint8_t pes_ext_flag             :1; /* PES extension flag. */
  uint8_t pes_crc_flag             :1; /* PES CRC flag. */
  uint8_t add_copy_info_flag       :1; /* Additional copy info flag*/
  uint8_t dsm_trick_mode_flag      :1; /* DSM trick mode flag. */
  uint8_t es_rate_flag             :1; /* Elementary stream flag. */
  uint8_t escr_flag                :1; /* ESCR flag. */
  uint8_t pts_dts_flags            :2; /* PTS/DTS flag. */
  /*Byte 9*/
  uint8_t header_data_length       :8; /* Length of optional fields and stuffing bytes. */
#endif
} tsmux_pes_header_t;

/**
 *
 * Scrambling control flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_SCRAMBLING_CTRL_NOT_SCRAMBLED = 0, /* Stream not scrambled. */
  MPEG_TS_PES_SCRAMBLING_CTRL_1             = 1, /* User defined. */
  MPEG_TS_PES_SCRAMBLING_CTRL_2             = 2, /* User defined. */
  MPEG_TS_PES_SCRAMBLING_CTRL_3             = 3  /* User defined. */
};

/**
 *
 * PES alignment flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_ALIGNMENT_CONTROL_UNKNOWN   = 0,/* No information about presence of startcodes. */
  MPEG_TS_PES_ALIGNMENT_CONTROL_STARTCODE = 1 /* The PES header packet is immediatelly followed by a video start code or audio syncword. */
};

/**
 *
 * PES alignment flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_COPYRIGHT_UNDEFINED = 0, /* The copyrights might be defined in a separate descriptor. */
  MPEG_TS_PES_COPYRIGHT_PROTECTED = 1  /* Material protected by copyrights. */
};

/**
 *
 * PES alignment flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_ORIGINAL_OR_COPY_COPY     = 0,/* Copied material. */
  MPEG_TS_PES_ORIGINAL_OR_COPY_ORIGINAL = 1 /* Original material. */
};

/**
 *
 * PES ESCR flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_ESCR_NOT_PRESENT = 0, /* ESCR base and extension fields are not present. */
  MPEG_TS_PES_ESCR_PRESENT     = 1  /* ESCR base and extension fields are present. */
};

/**
 *
 * Elementary stream flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_ES_NOT_PRESENT = 0, /* Elementary stream rate field is not present. */
  MPEG_TS_PES_ES_PRESENT     = 1  /* Elementary stream rate field is present. */
};

/**
 *
 * DSM trick mode flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_DSM_TRICK_MODE_NOT_PRESENT = 0, /* 8-bit trick mode field is not present. */
  MPEG_TS_PES_DSM_TRICK_MODE_PRESENT     = 1  /* 8-bit trick mode field is present. */
};

/**
 *
 * Add copy field flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_ADD_COPY_INFO_NOT_PRESENT = 0, /* Additional copy field is not present. */
  MPEG_TS_PES_ADD_COPY_INFO_PRESENT     = 1  /* Additional copy mode field is present. */
};

/**
 *
 * CRC flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_CRC_NOT_PRESENT = 0, /* CRC field is not present. */
  MPEG_TS_PES_CRC_PRESENT     = 1  /* CRC field is present. */
};

/**
 *
 * Extension flags as per "ISO/IEC 13818-1"
 */
enum {
  MPEG_TS_PES_EXT_NOT_PRESENT = 0, /* Extension field is not present. */
  MPEG_TS_PES_EXT_PRESENT     = 1  /* Extension field is present. */
};

typedef enum {
  TS_MEDIA_VIDEO = 0,
  TS_MEDIA_AUDIO
} ts_media_type_e;

typedef struct {
  ts_muxer_config_t config;

  uint8_t pat[TS_PACKET_SIZE];
  uint8_t pmt[TS_PACKET_SIZE];
  uint8_t video_pes[TS_PACKET_SIZE];
  uint8_t audio_pes[TS_PACKET_SIZE];

  tsmux_psi_pat_inf_t pat_info;
  tsmux_psi_pmt_inf_t pmt_info;
  tsmux_psi_prg_inf_t program_info_list;
  tsmux_psi_stream_inf_t video_stream_info;
  tsmux_psi_stream_inf_t audio_stream_info;
  uint8_t pmt_descriptor[4];
  uint8_t opus_descriptor[4];

  int32_t b_recv_first_h264_frame_i_frame;

  bool b_first_video;
  bool b_first_audio;
  uint64_t last_pat_pmt_refresh_pts;

  uint16_t last_video_ts;
  uint16_t last_audio_ts;
  uint64_t video_pts;
  uint64_t audio_pts;
  uint64_t first_video_pts;
  uint64_t first_audio_pts;
  int32_t  video_ts_wrapper_cnt;
  int32_t  audio_ts_wrapper_cnt;

  char *ts_slice;
  uint32_t ts_slice_pos;
  uint32_t ts_slice_buffer_size;
  char ts_slice_file_name[TS_FILE_NAME_BUF_SIZE];
  uint32_t ts_slice_latest_idx;
  uint64_t last_ts_slice_pts;

  char *m3u8;
  uint32_t m3u8_buffer_size;
  uint32_t m3u8_pos;
  uint32_t m3u8_ext_inf_latest_idx;
  bool b_first_m3u8_ts_slice;
  bool b_new_ts_slice;
} ts_muxer_t;

static void __crc32_Byte(int *preg, int x)
{
  int i;
  for (i = 0, x <<= 24; i < 8; ++i, x <<= 1) {
    (*preg) = ((*preg) << 1) ^ (((x ^ (*preg)) >> 31) & 0x04C11DB7);
  }
}

static int __cal_crc32(uint8_t * buf, int size)
{
  int crc = 0xffffffffL;
  for (int i = 0; i < size; ++i) {
    __crc32_Byte(&crc, (int)buf[i]);
  }
  return crc;
}

/**
 * @brief Initialize the PAT (Program Association Table) with the special information
 *
 * @param pat_info: The information of the PAT
 * @param pat: The buffer of PAT TS packet
 * @return int
 */
static int __create_pat(const tsmux_psi_pat_inf_t *pat_info, uint8_t *pat)
{
  /* Initialize the TS header */
  tsmux_ts_header_t *ts_header = (tsmux_ts_header_t *)pat;
  ts_header->sync_byte                    = TS_SYNC_BYTE;
  ts_header->transport_error_indicator    = MPEG_TS_TRANSPORT_ERROR_INDICATOR_NO_ERRORS;
  ts_header->payload_unit_start_indicator = MPEG_TS_PSUI_SET;
  ts_header->transport_priority           = MPEG_TS_TRANSPORT_PRIORITY_PRIORITY;
  ts_header->transport_scrambling_control = MPEG_TS_SCRAMBLING_CTRL_NOT_SCRAMBLED;
  ts_header->adaptation_field_control     = MPEG_TS_ADAPTATION_FIELD_PAYLOAD_ONLY;
  ts_header->continuity_counter           = 0;
  TSMUX_TS_HEADER_PID_SET(ts_header, TS_PAT_PID);

  /* Initialize the PAT, include PAT header and section */
  tsmux_pat_header_t *pat_header = NULL;
  if (MPEG_TS_PSUI_SET == ts_header->payload_unit_start_indicator) {
    /* payload pointer */
    pat[4] = 0x00;
    pat_header = (tsmux_pat_header_t *)(pat + 5);
  } else if (MPEG_TS_PSUI_UNSET == ts_header->payload_unit_start_indicator) {
    pat_header = (tsmux_pat_header_t *)(pat + 4);
  }
  /*TS hdr size + PSI pointer field*/
  uint8_t *pat_content = (uint8_t *)(((uint8_t *)pat_header) + PAT_HEADER_SIZE);

  int crc32 = 0;

  // PAT Header
  pat_header->table_id                 = MPTS_TABLE_ID_PROGRAM_ASSOCIATION;
  pat_header->section_syntax_indicator = 1;
  pat_header->b0                       = 0;
  pat_header->reserved0                = 0x3;
  pat_header->transport_stream_id_l    = 0x00;
  pat_header->transport_stream_id_h    = 0x00;
  pat_header->reserved1                = 0x3;
  pat_header->version_number           = 0x00;
  pat_header->current_next_indicator   = 1;     // indicates the version_number is sent to the current PAT
  pat_header->section_number           = 0x0;
  pat_header->last_section_number      = 0x0;
  pat_header->section_length0to7       = 0; //Update later
  pat_header->section_length8to11      = 0; //Update later

  // add informations for all programs (only one for now)
  pat_content[0] = (pat_info->program_info_list->pid_num >> 8) & 0xff;
  pat_content[1] = pat_info->program_info_list->pid_num & 0xff;
  pat_content[2] = 0xE0 | ((pat_info->program_info_list->pid_pmt & 0x1fff) >> 8);
  pat_content[3] = pat_info->program_info_list->pid_pmt & 0xff;
  pat_content   += 4;

  // update patHdr.section_length
  uint16_t section_len = pat_content + 4 - (uint8_t *)pat_header - 3 ;
  pat_header->section_length8to11 = (section_len & 0x0fff) >> 8;
  pat_header->section_length0to7  = (section_len & 0x00ff);

  // Calc CRC32
  crc32 = __cal_crc32((uint8_t*)pat_header, (int)(pat_content - (uint8_t *)pat_header));
  pat_content[0] = (crc32 >> 24) & 0xff;
  pat_content[1] = (crc32 >> 16) & 0xff;
  pat_content[2] = (crc32 >> 8) & 0xff;
  pat_content[3] = crc32 & 0xff;

  // Stuff rest of the packet
  memset(pat_content + 4, /*Stuffing Btypes*/ 0xff, TS_PACKET_SIZE - (pat_content + 4 - pat));
  return 0;
}

static void __update_psi_cnt(uint8_t* ts)
{
  ((tsmux_ts_header_t*)ts)->continuity_counter++;
}

static int __create_pmt(tsmux_psi_pmt_inf_t *pmt_info, uint8_t *pmt)
{
  tsmux_ts_header_t *ts_header = (tsmux_ts_header_t *)pmt;
  tsmux_pmt_header_t *pmt_header = (tsmux_pmt_header_t *)(pmt + 5);
  uint8_t *pmt_content = (uint8_t *)(((uint8_t *)pmt_header) + TS_PMT_HEADER_SIZE);
  int crc32;

  // TS HEADER
  ts_header->sync_byte                    = TS_SYNC_BYTE;
  ts_header->transport_error_indicator    = MPEG_TS_TRANSPORT_ERROR_INDICATOR_NO_ERRORS;
  ts_header->payload_unit_start_indicator = MPEG_TS_PSUI_SET;
  ts_header->transport_priority           = MPEG_TS_TRANSPORT_PRIORITY_PRIORITY;

  TSMUX_TS_HEADER_PID_SET(ts_header, pmt_info->program_info_list->pid_pmt);

  ts_header->transport_scrambling_control = MPEG_TS_SCRAMBLING_CTRL_NOT_SCRAMBLED;
  ts_header->adaptation_field_control     = MPEG_TS_ADAPTATION_FIELD_PAYLOAD_ONLY;
  ts_header->continuity_counter           = 0;

  // Set PSI poiter field
  pmt[4] = 0x00;

  // PMT HEADER
  pmt_header->table_id                 = 0x02;
  pmt_header->section_syntax_indicator = 1;
  pmt_header->b0                       = 0;
  pmt_header->reserved0                = 0x3;
  pmt_header->section_length0to7       = 0; //update later
  pmt_header->section_length8to11      = 0; //update later
  pmt_header->program_number_h         = (pmt_info->program_info_list->pid_num >> 8) & 0xff;
  pmt_header->program_number_l         = pmt_info->program_info_list->pid_num & 0xff;
  pmt_header->reserved1                = 0x3;
  pmt_header->version_number           = 0x0;
  pmt_header->current_next_indicator   = 1;
  pmt_header->section_number           = 0x0;
  pmt_header->last_section_number      = 0x0;
  pmt_header->reserved2                = 0x7;
  pmt_header->pcr_pid_8_to_12          = (pmt_info->program_info_list->pid_pcr >> 8) & 0x1f;
  pmt_header->pcr_pid_0_to_7           = pmt_info->program_info_list->pid_pcr & 0xff;
  pmt_header->reserved3                = 0xf;
  if (pmt_info->descriptor_len == 0) {
    pmt_header->program_info_length0to7  = 0;
    pmt_header->program_info_length8to11 = 0;
  } else {
    pmt_header->program_info_length8to11 = ((2 + pmt_info->descriptor_len) >> 8) & 0x0f;
    pmt_header->program_info_length0to7  = ((2 + pmt_info->descriptor_len) & 0xff);
  }

  if (pmt_info->descriptor_len > 0) {
    pmt_content[0] = pmt_info->descriptor_tag;
    pmt_content[1] = pmt_info->descriptor_len;
    memcpy(&pmt_content[2], pmt_info->descriptor, pmt_info->descriptor_len);
    pmt_content += (2 + pmt_info->descriptor_len);
  }

  // Add all stream elements
  for (uint16_t stream_cnt = 0; stream_cnt < pmt_info->stream_cnt; ++stream_cnt) {
    tsmux_psi_stream_inf_t * stream = pmt_info->stream[stream_cnt];
    pmt_element_t *pmt_element       = (pmt_element_t *)pmt_content;
    pmt_element->stream_type         = stream->type;
    pmt_element->reserved0           = 0x7; // 3 bits
    pmt_element->elementary_pid8to12 = ((stream->pid & 0x1fff) >> 8);
    pmt_element->elementary_pid0to7  = (stream->pid & 0xff);
    pmt_element->reserved1           = 0xf; // 4 bits
    pmt_element->es_info_length_h    = (((stream->descriptor_len + 2) >> 8) & 0x0f);
    pmt_element->es_info_length_l    = (stream->descriptor_len + 2) & 0xff;
    pmt_content                     += PMT_ELEMENT_SIZE;
    pmt_content[0]                   = stream->descriptor_tag; //descriptor_tag
    pmt_content[1]                   = stream->descriptor_len; //descriptor_length

    if (stream->descriptor_len > 0) {
      memcpy(&pmt_content[2], stream->descriptor, stream->descriptor_len);
    }

    pmt_content += (2 + stream->descriptor_len);
  }

  // update pmtHdr.section_length
  uint16_t section_len = pmt_content + 4 - ((uint8_t *)pmt_header + 3);
  pmt_header->section_length8to11 = (section_len >> 8) & 0x0f;
  pmt_header->section_length0to7  = (section_len & 0xff);

  // Calc CRC32
  crc32 = __cal_crc32((uint8_t*)pmt_header, (int)(pmt_content - (uint8_t*)pmt_header));
  pmt_content[0] = (crc32 >> 24) & 0xff;
  pmt_content[1] = (crc32 >> 16) & 0xff;
  pmt_content[2] = (crc32 >> 8) & 0xff;
  pmt_content[3] = crc32 & 0xff;

  // Stuff rest of the packet
  memset((pmt_content + 4), 0xff, (TS_PACKET_SIZE - (((uint8_t*)pmt_content + 4) - pmt)));
  return 0;
}

static int __create_ts_packet(tsmux_psi_stream_inf_t *stream, tsmux_pes_t* pes, uint8_t *ts_buf)
{
  tsmux_ts_header_t *ts_header = (tsmux_ts_header_t *)ts_buf;
  uint8_t *pes_packet = (uint8_t *)(ts_buf + TS_PACKET_HEADER_SIZE);
  uint8_t *pos;

  // precalculate pes_header_data_len so that Adapt filed can decide if stuffing is required
  uint32_t pes_pts_dts_flag = MPEG_TS_PTS_DTS_NO_PTSDTS;
  uint32_t pes_header_data_len = 0;// PES optional field data length
  if (pes->first_slice) {// the PES packet will start in the first slice
    //check pts dts delta
    if ((pes->pts <= (pes->dts + 1)) && (pes->dts <= (pes->pts + 1))) {
      pes_pts_dts_flag = MPEG_TS_PTS_DTS_PTS_ONLY;
      pes_header_data_len = PTS_FIELD_SIZE;
    } else {
      pes_pts_dts_flag = MPEG_TS_PTS_DTS_PTSDTS_BOTH;
      pes_header_data_len = PTS_FIELD_SIZE + DTS_FIELD_SIZE;
    }
  }

  // TS header
  ts_header->sync_byte                    = TS_SYNC_BYTE;
  ts_header->transport_error_indicator    = MPEG_TS_TRANSPORT_ERROR_INDICATOR_NO_ERRORS;
  ts_header->payload_unit_start_indicator = pes->first_slice ? // a PES starts in the current packet
                                            MPEG_TS_PSUI_SET :
                                            MPEG_TS_PSUI_UNSET;
  ts_header->transport_priority           = MPEG_TS_TRANSPORT_PRIORITY_NO_PRIORITY;
  ts_header->transport_scrambling_control = MPEG_TS_SCRAMBLING_CTRL_NOT_SCRAMBLED;
  ts_header->continuity_counter           = ((pes->first_frame && pes->first_slice) ? 0 : ((ts_buf[3] + 1) & 0x0f));// increase the counter
  TSMUX_TS_HEADER_PID_SET(ts_header, stream->pid);

  /* Adaptation field */
  /* For Transport Stream packets carrying PES packets, stuffing is needed when there is insufficient
     PES packet data to completely fill the Transport Stream packet payload bytes */
  tsmux_ts_adaptation_t *adapt_header = (tsmux_ts_adaptation_t *)(ts_buf + TS_PACKET_HEADER_SIZE);
  pos = (uint8_t *)adapt_header;// point to adapt header

  // fill the common fields
  adapt_header->adaptation_field_length              = 0;
  adapt_header->adaptation_field_extension_flag      = MPEG_TS_ADAPTATION_FIELD_EXTENSION_NOT_PRESENT;
  adapt_header->transport_private_data_flag          = MPEG_TS_TRANSPORT_PRIVATE_DATA_NOT_PRESENT;
  adapt_header->splicing_point_flag                  = MPEG_TS_SPLICING_POINT_FLAG_NOT_PRESENT;
  adapt_header->opcr_flag                            = MPEG_TS_OPCR_FLAG_NOT_PRESENT;
  adapt_header->pcr_flag                             = MPEG_TS_PCR_FLAG_NOT_PRESENT;
  adapt_header->elementary_stream_priority_indicator = MPEG_TS_ELEMENTARY_STREAM_PRIORITY_NO_PRIORITY;
  adapt_header->random_access_indicator              = MPEG_TS_RANDOM_ACCESS_INDICATOR_NOT_PRESENT;
  adapt_header->discontinuity_indicator              = MPEG_TS_DISCONTINUITY_INDICATOR_NO_DISCONTINUTY;//assume no discontinuity occur

  int32_t init_adapt_filed_size = 0;
  if (pes->with_pcr) {
    adapt_header->adaptation_field_length = 1 + PCR_FIELD_SIZE; //# of bytes following adaptation_field_length (1 + 6 pcr size)
    adapt_header->pcr_flag                = MPEG_TS_PCR_FLAG_PRESENT;
    adapt_header->random_access_indicator = MPEG_TS_RANDOM_ACCESS_INDICATOR_PRESENT;

    pos += ADAPT_HEADER_LEN;//skip adapt hdr and point to optional field (PCR field)
    pos[0] = pes->pcr_base >> 25;
    pos[1] = (pes->pcr_base & 0x1fe0000) >> 17;
    pos[2] = (pes->pcr_base & 0x1fe00) >> 9;
    pos[3] = (pes->pcr_base & 0x1fe) >> 1;
    pos[4] = ((pes->pcr_base & 0x1) << 7) | (0x7e) | (pes->pcr_ext >> 8);
    pos[5] = pes->pcr_ext & 0xff;
    pos += PCR_FIELD_SIZE;// point to the start of potential stuffing area
    init_adapt_filed_size = adapt_header->adaptation_field_length + 1;
  }

  // check if stuffing is required and calculate stuff size
  uint32_t pes_header_size = 0;
  int32_t stuff_size = 0;

  if (pes->first_slice) {
    pes_header_size = PES_HEADER_LEN + pes_header_data_len;
  }

  int32_t pes_payload_space = TS_PACKET_SIZE - TS_PACKET_HEADER_SIZE - init_adapt_filed_size - pes_header_size;
  if (pes->payload_len < pes_payload_space) {
    stuff_size = pes_payload_space - pes->payload_len;
  }

  if (stuff_size > 0) {// need stuffing
    int32_t real_stuff_size = stuff_size;

    if (init_adapt_filed_size == 0) {// adapt header is not written yet
      if (stuff_size == 1) {
        pos++;// write the adapt_field_length byte (=0)
        real_stuff_size--;
      } else {
        pos += 2;// write the two byte adapt header
        real_stuff_size -= 2;
        adapt_header->adaptation_field_length = 1;// adaptation_field_length 0 --> 1
      }
    }

    if (real_stuff_size > 0) {// stuff size should be >= 2
      // pos should point to the start of stuffing area
      memset(pos, 0xff, real_stuff_size);
      pos += real_stuff_size;
      adapt_header->adaptation_field_length += real_stuff_size;
    }
  }

  // update adaptation_field_control of TS header
  ts_header->adaptation_field_control = (pes->with_pcr || stuff_size > 0) ?
                                         MPEG_TS_ADAPTATION_FIELD_BOTH :
                                         MPEG_TS_ADAPTATION_FIELD_PAYLOAD_ONLY;

  // calcuate the start addr of PES packet
  pes_packet = pos;

  /* TS packet payload (PES header + PES payload or PES playload only) */
  if (ts_header->payload_unit_start_indicator) {// one PES packet is started in this transport packet
    tsmux_pes_header_t *pes_header = (tsmux_pes_header_t *)pes_packet;

    pes_header->packet_start_code_23to16 = 0;
    pes_header->packet_start_code_15to8  = 0;
    pes_header->packet_start_code_7to0   = 0x01;
    pes_header->marker_bits              = 2;
    pes_header->pes_scrambling_control   = MPEG_TS_PES_SCRAMBLING_CTRL_NOT_SCRAMBLED;
    pes_header->pes_priority             = 0;
    pes_header->data_alignment_indicator = MPEG_TS_PES_ALIGNMENT_CONTROL_STARTCODE;
    pes_header->copyright                = MPEG_TS_PES_COPYRIGHT_UNDEFINED;
    pes_header->original_or_copy         = MPEG_TS_PES_ORIGINAL_OR_COPY_COPY;
    pes_header->escr_flag                = MPEG_TS_PES_ESCR_NOT_PRESENT;
    pes_header->es_rate_flag             = MPEG_TS_PES_ES_NOT_PRESENT;
    pes_header->dsm_trick_mode_flag      = MPEG_TS_PES_DSM_TRICK_MODE_NOT_PRESENT;
    pes_header->add_copy_info_flag       = MPEG_TS_PES_ADD_COPY_INFO_NOT_PRESENT;
    pes_header->pes_crc_flag             = MPEG_TS_PES_CRC_NOT_PRESENT;
    pes_header->pes_ext_flag             = MPEG_TS_PES_EXT_NOT_PRESENT;
    pes_header->pts_dts_flags            = pes_pts_dts_flag;
    pes_header->header_data_length       = pes_header_data_len;

    // Set stream_id & pes_packet_size
    uint16_t pes_packet_size;
    if (stream->type == MPEG_SI_STREAM_TYPE_AVC_VIDEO ||
        stream->type == MPEG_SI_STREAM_TYPE_JPEG) {
      pes_header->stream_id = MPEG_TS_STREAM_ID_VIDEO_00;
      if (pes->payload_len < (TS_PACKET_SIZE - (((uint8_t *)pes_packet) - ts_buf) /* TS header + adaptation field */
                              - PES_HEADER_LEN - pes_header->header_data_length)) {
        pes_packet_size = 3 + pes_header->header_data_length + (pes->payload_len);// 3 bytes following PES_packet_length field
      } else {
        pes_packet_size = 0;
      }
    } else if (stream->type == MPEG_SI_STREAM_TYPE_AAC) {
      pes_header->stream_id = MPEG_TS_STREAM_ID_AUDIO_00;
      pes_packet_size = 3 + pes_header->header_data_length + (pes->payload_len);// 3 bytes following PES_packet_length field
    } else if (stream->type == MPEG_SI_STREAM_TYPE_G722_16K ||
               stream->type == MPEG_SI_STREAM_TYPE_G722_8K ||
               stream->type == MPEG_SI_STREAM_TYPE_ALAW ||
               stream->type == MPEG_SI_STREAM_TYPE_MULAW) {
      pes_header->stream_id = MPEG_TS_STREAM_ID_AUDIO_00;
      pes_packet_size = 3 + pes_header->header_data_length + (pes->payload_len);// 3 bytes following PES_packet_length field
    } else if (stream->type == MPEG_SI_STREAM_TYPE_OPUS) {
      pes_header->stream_id = MPEG_TS_STREAM_ID_AUDIO_00;
      pes_packet_size = 3 + pes_header->header_data_length + (pes->payload_len);// 3 bytes following PES_packet_length field
    } else if (stream->type == MPEG_SI_STREAM_TYPE_LPCM_AUDIO) {
      pes_header->stream_id = MPEG_TS_STREAM_ID_PRIVATE_STREAM_1;
      pes_packet_size = 3 + pes_header->header_data_length + (pes->payload_len) + 4;// add 4 bytes for LPCMAudioDataHeader
    } else {
      return -1;
    }

    pes_header->pes_packet_length_15to8 = ((pes_packet_size) >> 8) & 0xff;
    pes_header->pes_packet_length_7to0  = (pes_packet_size) & 0xff;

    // point to PES header optional field
    pos += PES_HEADER_LEN;

    switch (pes_header->pts_dts_flags) {
      case MPEG_TS_PTS_DTS_NO_PTSDTS:
        break;
      case MPEG_TS_PTS_DTS_PTS_ONLY: {
          pos[0] = 0x21 | (((pes->pts >> 30) & 0x07) << 1);
          pos[1] = ((pes->pts >> 22) & 0xff);
          pos[2] = (((pes->pts >> 15) & 0x7f) << 1) | 0x1;
          pos[3] = ((pes->pts >> 7) & 0xff);
          pos[4] = ((pes->pts & 0x7f) << 1) | 0x1;
        }
        break;
      case MPEG_TS_PTS_DTS_PTSDTS_BOTH: {
          pos[0] = 0x31 | (((pes->pts >> 30) & 0x07) << 1);
          pos[1] = ((pes->pts >> 22) & 0xff);
          pos[2] = (((pes->pts >> 15) & 0x7f) << 1) | 0x1;
          pos[3] = ((pes->pts >> 7) & 0xff);
          pos[4] = ((pes->pts & 0x7f) << 1) | 0x1;
          pos[5] = 0x11 | (((pes->dts >> 30) & 0x07) << 1);
          pos[6] = ((pes->dts >> 22) & 0xff);
          pos[7] = (((pes->dts >> 15) & 0x7f) << 1) | 0x1;
          pos[8] = ((pes->dts >> 7) & 0xff);
          pos[9] = ((pes->dts & 0x7f) << 1) | 0x1;
        }
        break;
      default:
        break;
    }

    if (stream->type == MPEG_SI_STREAM_TYPE_LPCM_AUDIO) {
      //AVCHDLPCMAudioDataHeader() {
      //      AudioDataPayloadSize 16
      //      ChannelAssignment     4      3 for stereo
      //      SamplingFrequency     4      1 for 48kHz
      //      BitPerSample          2      1 for 16-bit
      //      StartFlag             1
      //      reserved              5
      //}
      pos[0] = (pes->payload_len >> 8) & 0xFF;//0x03
      pos[1] = pes->payload_len & 0xFF;//0xC0;
      pos[2] = 0x31; //48kHz stereo
      pos[3] = 0x60; //16 bits per sample
    }
    pos += pes_header->header_data_length;
  }

  // pos should be the latest write point
  int payload_fill_size = TS_PACKET_SIZE - (pos - ts_buf);
  assert(payload_fill_size <= pes->payload_len);
  memcpy(pos, pes->payload, payload_fill_size);
  return payload_fill_size;
}

static void __enlarge_m3u8_buffer_when_necessary(ts_muxer_t *ts_muxer,
                                                 int newly_increased_m3u8_tag_len)
{
  char *tmp;
  if (ts_muxer->m3u8_pos + newly_increased_m3u8_tag_len >= ts_muxer->m3u8_buffer_size) {
    assert(newly_increased_m3u8_tag_len < M3U8_BUFFER_SIZE);
    tmp = (char *)malloc(ts_muxer->m3u8_buffer_size + M3U8_BUFFER_SIZE);
    assert(tmp);

    memcpy(tmp, ts_muxer->m3u8, ts_muxer->m3u8_pos); //donot need copy '\0'
    free(ts_muxer->m3u8);

    ts_muxer->m3u8 = tmp;
    ts_muxer->m3u8_buffer_size += M3U8_BUFFER_SIZE;
    LOGD(TAG, "M3U8 buffer enlarge done. len=%u", ts_muxer->m3u8_buffer_size);
  }
}

static void __build_m3u8_header(ts_muxer_t *ts_muxer, uint64_t pts)
{
  uint32_t duration;

  /* only first ts slice need append m3u8 header */
  if (!ts_muxer->b_first_m3u8_ts_slice) {
    return;
  }

  /* set b_first_m3u8_ts_slice false */
  ts_muxer->b_first_m3u8_ts_slice = false;

  /* generate m3u8 header */
  duration = (pts - ts_muxer->last_ts_slice_pts) / 90000 + 2; /* add 2s for possible timestamp fluctuations */
  snprintf(ts_muxer->m3u8, M3U8_BUFFER_SIZE, /* donnot use snprintf return value */
           "#EXTM3U\r\n"
           "#EXT-X-VERSION:3\r\n"
           "#EXT-X-MEDIA-SEQUENCE:0\r\n"
           "#EXT-X-ALLOW-CACHE:YES\r\n"
           "#EXT-X-TARGETDURATION:%u\r\n", duration);

  /* move m3u8_pos */
  ts_muxer->m3u8_pos = strlen(ts_muxer->m3u8);

  LOGD(TAG, "M3u8[%u]:\r\n%s", ts_muxer->m3u8_pos, ts_muxer->m3u8);
}

static void __append_m3u8_extinf(ts_muxer_t *ts_muxer, char *ts_file_name, uint64_t pts)
{
  char m3u8_extinf[128];
  int m3u8_extinf_len;
  uint32_t duration;

  /* separate without the path */
  char *file_name = strrchr(ts_file_name, '/');
  if (!file_name) {
    file_name = ts_file_name;
  } else {
    /* jump the character '/' */
    file_name += 1;
  }

  LOGD(TAG, "file_name: %s", file_name);

  /* calculate this slice length */
  duration = (pts - ts_muxer->last_ts_slice_pts) / 90000;
  snprintf(m3u8_extinf, sizeof(m3u8_extinf),
           "#EXTINF:%u\r\n"
           "%s\r\n",
           duration,
           file_name);
  m3u8_extinf_len = strlen(m3u8_extinf);

  /* m3u8 buffer capacity validate */
  __enlarge_m3u8_buffer_when_necessary(ts_muxer, m3u8_extinf_len);

  /* write m3u8 extinf */
  strcpy(ts_muxer->m3u8 + ts_muxer->m3u8_pos, m3u8_extinf);
  ts_muxer->m3u8_pos += m3u8_extinf_len;

  /* update extinf index */
  ts_muxer->m3u8_ext_inf_latest_idx++;

  LOGD(TAG, "M3U8. pos=%u, size=%u, len=%d\r\n%s", ts_muxer->m3u8_pos,
       ts_muxer->m3u8_buffer_size, m3u8_extinf_len, ts_muxer->m3u8);
}

static void __append_m3u8_endlist(ts_muxer_t *ts_muxer)
{
  /* m3u8 buffer capacity validate */
  __enlarge_m3u8_buffer_when_necessary(ts_muxer, M3U8_ENDLIST_TAG_LEN);

  /* write m3u8 endlist */
  strcpy(ts_muxer->m3u8 + ts_muxer->m3u8_pos, M3U8_ENDLIST_TAG);

  if (!ts_muxer->config.gen_m3u8_file_for_every_ts_slice) {
    ts_muxer->m3u8_pos += M3U8_ENDLIST_TAG_LEN;
  }

  LOGD(TAG, "M3U8. pos=%u, size=%u, len=%d\r\n%s", ts_muxer->m3u8_pos,
       ts_muxer->m3u8_buffer_size, M3U8_ENDLIST_TAG_LEN, ts_muxer->m3u8);
}

static void __cache_ts_slice_to_memory(uint8_t *data, int len, ts_muxer_t *ts_muxer)
{
  char *tmp;

  /* enlarge ts_slice buffer when necessary */
  if (ts_muxer->ts_slice_pos +
      len +
      (ts_muxer->config.enable_aes_cbc_encrypt_with_pkcs7_padding ? EASY_AES_BLOCKLEN : 0) > /* for pkcs#7 padding zero copy */
      ts_muxer->ts_slice_buffer_size) {
    tmp = (char *)malloc(ts_muxer->ts_slice_buffer_size + TS_SLICE_BUF_SIZE);
    memcpy(tmp, ts_muxer->ts_slice, ts_muxer->ts_slice_pos);
    free(ts_muxer->ts_slice);
    ts_muxer->ts_slice = tmp;
    ts_muxer->ts_slice_buffer_size += TS_SLICE_BUF_SIZE;

    LOGD(TAG, "enlarge ts_slice done. size=%u", ts_muxer->ts_slice_buffer_size);
  }

  /* save data to ts_slice buffer */
  memcpy(ts_muxer->ts_slice + ts_muxer->ts_slice_pos, data, len);

  /* move ts_slice_pos to next write ptr header */
  ts_muxer->ts_slice_pos += len;

  LOGD(TAG, "TS-SLICE. pos=%u, size=%u, len=%d", ts_muxer->ts_slice_pos,
       ts_muxer->ts_slice_buffer_size, len);
}

static void __write(char *data, size_t len, char *file_name, write_func_t write_handler, void *user_data)
{
  assert(write_handler);
  write_handler(data, len, file_name, user_data);
}

static void __write_m3u8(ts_muxer_t *ts_muxer)
{
  size_t m3u8_len = ts_muxer->m3u8_pos;
  char m3u8_file_name[256];

  snprintf(m3u8_file_name, sizeof(m3u8_file_name), "%s.m3u8", ts_muxer->config.ts_slice_file_name_prefix);
  LOGT(TAG, "m3u8 file name=%s", m3u8_file_name);

  if (ts_muxer->config.gen_m3u8_file_for_every_ts_slice) {
    m3u8_len += M3U8_ENDLIST_TAG_LEN;
  }

  __write(ts_muxer->m3u8, m3u8_len, m3u8_file_name, ts_muxer->config.write_handler, ts_muxer->config.user_data);
}

static void __write_ts_slice(ts_muxer_t *ts_muxer)
{
  size_t actual_len = ts_muxer->ts_slice_pos;
  if (ts_muxer->config.enable_aes_cbc_encrypt_with_pkcs7_padding) {
    uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    __easy_aes_cbc_encrypt(iv, ts_muxer->config.aes_cbc_encrypt_key, (uint8_t *)ts_muxer->ts_slice, &actual_len);
  }
  __write(ts_muxer->ts_slice, actual_len, ts_muxer->ts_slice_file_name, ts_muxer->config.write_handler, ts_muxer->config.user_data);
}

static void __write_ts_packet(uint8_t *data, int len, bool vpes_keyframe, uint64_t pts, ts_muxer_t *ts_muxer)
{
  /**
   * finish one ts slice and append m3u8 extinf
   */
  if (vpes_keyframe &&
      pts > ts_muxer->last_ts_slice_pts &&
      pts - ts_muxer->last_ts_slice_pts >= ts_muxer->config.ts_slice_second * 90000) {

    LOGD(TAG, "slice. last=%" PRIu64", pts=%" PRIu64", ts_idx=%u, m3u8_extinf_idx=%u",
         ts_muxer->last_ts_slice_pts, pts,
         ts_muxer->ts_slice_latest_idx,
         ts_muxer->m3u8_ext_inf_latest_idx);

    /* write ts slice to flash or push to OSS... */
    __write_ts_slice(ts_muxer);

    /* build m3u8 header */
    __build_m3u8_header(ts_muxer, pts);

    /* append m3u8 extinf */
    __append_m3u8_extinf(ts_muxer, ts_muxer->ts_slice_file_name, pts);

    /* write m3u8 when configure */
    if (ts_muxer->config.gen_m3u8_file_for_every_ts_slice) {
      __append_m3u8_endlist(ts_muxer);
      __write_m3u8(ts_muxer);
    }

    /* reset ts_slice_pos */
    ts_muxer->ts_slice_pos = 0;

    /* save the last ts slice pts, used for calculating new ts slice end */
    ts_muxer->last_ts_slice_pts = pts;

    /* set b_new_ts_slice to true */
    ts_muxer->b_new_ts_slice = true;
  }

  /**
   * the beginning of building a new slice ts
   */
  if (ts_muxer->b_new_ts_slice) {

    /* update ts slice index */
    ts_muxer->ts_slice_latest_idx++;

    /* generate ts slice file name */
    snprintf(ts_muxer->ts_slice_file_name, sizeof(ts_muxer->ts_slice_file_name),
             "%s_%u.ts",
             ts_muxer->config.ts_slice_file_name_prefix,
             ts_muxer->ts_slice_latest_idx);

    LOGD(TAG, "ts slice file name=%s", ts_muxer->ts_slice_file_name);

    /* set b_new_ts_slice to false */
    ts_muxer->b_new_ts_slice = false;
  }

  /**
   * cache ts slice to ts_slice buffer
   */
  __cache_ts_slice_to_memory(data, len, ts_muxer);
}

static void __set_current_pat_pmt_refresh_pts(ts_muxer_t *ts_muxer, uint64_t pts)
{
  ts_muxer->last_pat_pmt_refresh_pts = pts;
}

static void __try_refresh_pat_pmt_info(ts_muxer_t *ts_muxer, uint64_t pts, bool keyframe)
{
  if (keyframe ||
      pts + (ts_muxer->audio_pts - ts_muxer->last_audio_ts * 90) - ts_muxer->last_pat_pmt_refresh_pts >= 45000 || /* 90khz, 45K for 500ms */
      pts + (ts_muxer->video_pts - ts_muxer->last_video_ts * 90) - ts_muxer->last_pat_pmt_refresh_pts >= 45000) {
    __write_ts_packet(ts_muxer->pat, TS_PACKET_SIZE, keyframe, pts, ts_muxer);
    __write_ts_packet(ts_muxer->pmt, TS_PACKET_SIZE, keyframe, pts, ts_muxer);
    __update_psi_cnt(ts_muxer->pat);
    __update_psi_cnt(ts_muxer->pmt);
    __set_current_pat_pmt_refresh_pts(ts_muxer, pts);
  }
}

static bool  __pts_validate(ts_muxer_t *ts_muxer)
{
  /* first pts must be valid */
  if (ts_muxer->video_pts == DEFAULT_PTS || ts_muxer->audio_pts == DEFAULT_PTS) {
    return true;
  }

  /* latest video pts exceeds audio pts by more than 500 milliseconds  */
  if (ts_muxer->video_pts > ts_muxer->audio_pts) {
    return ts_muxer->video_pts - ts_muxer->audio_pts > 45000 ? false : true;  /* 90khz, 45K for 500ms */
  }

  /* latest audio pts exceeds video pts by more than 500 milliseconds  */
  return ts_muxer->audio_pts - ts_muxer->video_pts > 45000 ? false : true;  /* 90khz, 45K for 500ms */
}

static void __audio_pes_process(ts_muxer_t *ts_muxer, uint8_t *data, uint32_t len, uint64_t pts)
{
  tsmux_pes_t audio_payload_info;
  audio_payload_info.first_frame = ts_muxer->b_first_audio;
  audio_payload_info.with_pcr    = 0;
  audio_payload_info.first_slice = 1;
  audio_payload_info.payload     = data;
  audio_payload_info.payload_len = len;
  audio_payload_info.pcr_base    = pts;
  audio_payload_info.pcr_ext     = 0;
  audio_payload_info.pts         = pts;
  audio_payload_info.dts         = pts;

  LOGD(TAG, "audio pts=%" PRIu64", pcr_base=%" PRIu64", pcr_ext=%u", pts,
       audio_payload_info.pcr_base, audio_payload_info.pcr_ext);

  while (audio_payload_info.payload_len > 0) {
    int write_len;
    write_len = __create_ts_packet(&ts_muxer->audio_stream_info,
                                   &audio_payload_info, ts_muxer->audio_pes);
    __write_ts_packet(ts_muxer->audio_pes, TS_PACKET_SIZE, false, pts, ts_muxer);
    audio_payload_info.first_slice  = 0;
    audio_payload_info.payload     += write_len;
    audio_payload_info.payload_len -= write_len;
  }

  ts_muxer->b_first_audio = false;
}

static void __video_pes_process(ts_muxer_t *ts_muxer, uint8_t *data,
                                uint32_t len, uint64_t pts, bool keyframe)
{
  tsmux_pes_t video_payload_info;
  video_payload_info.first_frame = ts_muxer->b_first_video;
  video_payload_info.with_pcr    = 1;
  video_payload_info.first_slice = 1;
  video_payload_info.payload     = data;
  video_payload_info.payload_len = len;
  video_payload_info.pcr_base    = pts;
  video_payload_info.pcr_ext     = 0;
  video_payload_info.pts         = pts;
  video_payload_info.dts         = pts;

  if (ts_muxer->b_recv_first_h264_frame_i_frame == -1) {
    ts_muxer->b_recv_first_h264_frame_i_frame = keyframe ? 1 : 0;
  }

  if (ts_muxer->b_recv_first_h264_frame_i_frame != 1) {
    LOGW(TAG, "first h264 not I frame. please check your config");
  }

  LOGD(TAG, "video pts=%" PRIu64", dts=%" PRIu64", pcr_base=%" PRIu64", pcr_ext=%u",
       video_payload_info.pts, video_payload_info.dts,
       video_payload_info.pcr_base, video_payload_info.pcr_ext);

  while (video_payload_info.payload_len > 0) {
    int write_len = __create_ts_packet(&ts_muxer->video_stream_info,
                                       &video_payload_info,
                                       ts_muxer->video_pes);

    __write_ts_packet(ts_muxer->video_pes, TS_PACKET_SIZE, keyframe, pts, ts_muxer);
    video_payload_info.with_pcr     = 0;
    video_payload_info.first_slice  = 0;
    video_payload_info.payload     += write_len;
    video_payload_info.payload_len -= write_len;
  }

  ts_muxer->b_first_video = false;
}

static void __feed_media_data(ts_muxer_t *ts_muxer, ts_media_type_e type,
                              uint8_t *data, uint32_t len, uint64_t pts, bool keyframe)
{
  if (ts_muxer->last_ts_slice_pts == 0) {
    ts_muxer->last_ts_slice_pts = pts + 1; //cover pts = 0;
  }

  __try_refresh_pat_pmt_info(ts_muxer, pts, keyframe);

  switch (type) {
    case TS_MEDIA_AUDIO:
      __audio_pes_process(ts_muxer, data, len, pts);
      break;
    case TS_MEDIA_VIDEO:
      __video_pes_process(ts_muxer, data, len, pts, keyframe);
      break;
    default:
      break;
  }
}

int ts_muxer_feed_audio(ts_muxer_handle_t handle, uint8_t *data, uint32_t len, uint16_t timestamp_in_msec)
{
  ts_muxer_t *ts_muxer = (ts_muxer_t *)handle;
  assert(ts_muxer);

  if (ts_muxer->last_audio_ts > timestamp_in_msec) {
    ts_muxer->audio_pts += (UINT16_MAX - ts_muxer->last_audio_ts + timestamp_in_msec) * 90;
    ts_muxer->audio_pts %= MAX_PTS;
    ts_muxer->audio_ts_wrapper_cnt++;
  } else {
    ts_muxer->audio_pts += (timestamp_in_msec - ts_muxer->last_audio_ts) * 90;
    ts_muxer->audio_pts %= MAX_PTS;
  }

  if (ts_muxer->first_audio_pts == -1) ts_muxer->first_audio_pts = ts_muxer->audio_pts;

  if (ts_muxer->b_first_audio && !ts_muxer->b_first_video) {
    if (ts_muxer->first_video_pts > ts_muxer->audio_pts && ts_muxer->first_video_pts - ts_muxer->audio_pts > 32768) {
      ts_muxer->audio_pts += UINT16_MAX * 90;
    } else if (ts_muxer->audio_pts > ts_muxer->first_video_pts && ts_muxer->audio_pts - ts_muxer->first_video_pts > 32768) {
      ts_muxer->audio_pts -= UINT16_MAX * 90;
    }
  }

  if (!__pts_validate(ts_muxer)) {
    LOGW(TAG, "apts invalid[%u,%u]. vpts=%" PRIu64", apts=%" PRIu64", offset=%dms, atsw=%d, vtsw=%d",
         timestamp_in_msec, ts_muxer->last_audio_ts, ts_muxer->video_pts, ts_muxer->audio_pts,
         (int)abs((int64_t)(ts_muxer->video_pts - ts_muxer->audio_pts)) / 90,
         ts_muxer->audio_ts_wrapper_cnt, ts_muxer->video_ts_wrapper_cnt);
  }

  __feed_media_data(ts_muxer, TS_MEDIA_AUDIO, data, len, ts_muxer->audio_pts, false);
  ts_muxer->last_audio_ts = timestamp_in_msec;

  return 0;
}

int ts_muxer_feed_video(ts_muxer_handle_t handle, uint8_t *data, uint32_t len, uint16_t timestamp_in_msec, bool keyframe)
{
  ts_muxer_t *ts_muxer = (ts_muxer_t *)handle;
  assert(ts_muxer);

  if (ts_muxer->last_video_ts > timestamp_in_msec) {
    ts_muxer->video_pts += (UINT16_MAX - ts_muxer->last_video_ts + timestamp_in_msec) * 90;
    ts_muxer->video_pts %= MAX_PTS;
    ts_muxer->video_ts_wrapper_cnt++;
  } else {
    ts_muxer->video_pts += (timestamp_in_msec - ts_muxer->last_video_ts) * 90;
    ts_muxer->video_pts %= MAX_PTS;
  }

  if (ts_muxer->first_video_pts == -1) ts_muxer->first_video_pts = ts_muxer->video_pts;

  if (ts_muxer->b_first_video && !ts_muxer->b_first_audio) {
    if (ts_muxer->video_pts > ts_muxer->first_audio_pts && ts_muxer->video_pts - ts_muxer->first_audio_pts > 32768) {
      ts_muxer->video_pts -= UINT16_MAX * 90;
    } else if (ts_muxer->first_audio_pts > ts_muxer->video_pts && ts_muxer->first_audio_pts - ts_muxer->video_pts > 32768) {
      ts_muxer->video_pts += UINT16_MAX * 90;
    }
  }

  if (!__pts_validate(ts_muxer)) {
    LOGW(TAG, "vpts invalid[%u,%u]. vpts=%" PRIu64", apts=%" PRIu64", offset=%dms, atsw=%d, vtsw=%d",
         timestamp_in_msec, ts_muxer->last_video_ts, ts_muxer->video_pts, ts_muxer->audio_pts,
         (int)abs((int64_t)(ts_muxer->video_pts - ts_muxer->audio_pts)) / 90,
         ts_muxer->audio_ts_wrapper_cnt, ts_muxer->video_ts_wrapper_cnt);
  }

  __feed_media_data(ts_muxer, TS_MEDIA_VIDEO, data, len, ts_muxer->video_pts, keyframe);
  ts_muxer->last_video_ts = timestamp_in_msec;

  return 0;
}

static int32_t __audio_type_parse(ts_audio_type_e type)
{
  switch (type) {
    case TS_AUDIO_TYPE_AAC_LC:
      return MPEG_SI_STREAM_TYPE_AAC;
    case TS_AUDIO_TYPE_G722_16K:
      return MPEG_SI_STREAM_TYPE_G722_16K;
    case TS_AUDIO_TYPE_G722_8K:
      return MPEG_SI_STREAM_TYPE_G722_8K;
    case TS_AUDIO_TYPE_OPUS:
      return MPEG_SI_STREAM_TYPE_OPUS;
    case TS_AUDIO_TYPE_G711A:
      return MPEG_SI_STREAM_TYPE_ALAW;
    case TS_AUDIO_TYPE_G711U:
      return MPEG_SI_STREAM_TYPE_MULAW;
    default:
      assert(false);
      break;
  }

  return 0;
}

static int32_t __video_type_parse(ts_video_type_e type)
{
  switch (type) {
    case TS_VIDEO_TYPE_H264:
      return MPEG_SI_STREAM_TYPE_AVC_VIDEO;
    case TS_VIDEO_TYPE_JPEG:
      return MPEG_SI_STREAM_TYPE_JPEG;
    default:
      assert(false);
      break;
  }

  return 0;
}

ts_muxer_handle_t ts_muxer_create(ts_muxer_config_t *config)
{
  ts_muxer_t *ts_muxer = (ts_muxer_t *)malloc(sizeof(ts_muxer_t));
  assert(ts_muxer && config);
  memset(ts_muxer, 0, sizeof(ts_muxer_t));
  memcpy(&ts_muxer->config, config, sizeof(ts_muxer_config_t));

  ts_muxer->b_first_audio = true;
  ts_muxer->b_first_video = true;
  ts_muxer->last_audio_ts = 0;
  ts_muxer->last_video_ts = 0;
  ts_muxer->audio_pts     = DEFAULT_PTS;
  ts_muxer->video_pts     = DEFAULT_PTS;
  ts_muxer->first_audio_pts = -1;
  ts_muxer->first_video_pts = -1;
  ts_muxer->last_pat_pmt_refresh_pts = 0;
  ts_muxer->last_ts_slice_pts        = 0;

  ts_muxer->b_recv_first_h264_frame_i_frame = -1;

  ts_muxer->m3u8_ext_inf_latest_idx  = 0;
  ts_muxer->b_first_m3u8_ts_slice    = true;
  ts_muxer->m3u8_pos                 = 0;
  ts_muxer->m3u8_buffer_size         = M3U8_BUFFER_SIZE;
  ts_muxer->m3u8                     = (char *)malloc(M3U8_BUFFER_SIZE);
  assert(ts_muxer->m3u8);

  ts_muxer->ts_slice_latest_idx  = 0;
  ts_muxer->ts_slice_buffer_size = TS_SLICE_BUF_SIZE;
  ts_muxer->ts_slice_pos         = 0;
  ts_muxer->b_new_ts_slice       = true;
  ts_muxer->ts_slice             = (char *)malloc(TS_SLICE_BUF_SIZE);
  assert(ts_muxer->ts_slice);

  ts_muxer->video_stream_info.pid            = 0x100;
  ts_muxer->video_stream_info.type           = __video_type_parse(ts_muxer->config.video_type);
  ts_muxer->video_stream_info.descriptor_tag = 0x51;
  ts_muxer->video_stream_info.descriptor     = NULL;
  ts_muxer->video_stream_info.descriptor_len = 0;

  ts_muxer->audio_stream_info.pid            = 0x101;
  ts_muxer->audio_stream_info.type           = __audio_type_parse(ts_muxer->config.audio_type);
  if (ts_muxer->audio_stream_info.type == MPEG_SI_STREAM_TYPE_OPUS) {
    ts_muxer->audio_stream_info.descriptor_tag = 0x05;
    ts_muxer->audio_stream_info.descriptor_len = 4;
    ts_muxer->audio_stream_info.descriptor     = ts_muxer->opus_descriptor;
    ts_muxer->audio_stream_info.descriptor[0]  = 'O';
    ts_muxer->audio_stream_info.descriptor[1]  = 'p';
    ts_muxer->audio_stream_info.descriptor[2]  = 'u';
    ts_muxer->audio_stream_info.descriptor[3]  = 's';
  } else {
    ts_muxer->audio_stream_info.descriptor_tag = 0x52;
    ts_muxer->audio_stream_info.descriptor_len = 0;
    ts_muxer->audio_stream_info.descriptor     = NULL;
  }

  ts_muxer->program_info_list.pid_pmt  = 0x1000;
  ts_muxer->program_info_list.pid_pcr  = 0x100;
  ts_muxer->program_info_list.pid_num  = 1;
  ts_muxer->pat_info.total_programs    = 1;
  ts_muxer->pat_info.program_info_list = &ts_muxer->program_info_list;

  ts_muxer->pmt_info.stream_cnt        = 2;
  ts_muxer->pmt_info.program_info_list = &ts_muxer->program_info_list;
  ts_muxer->pmt_info.stream[0]         = &ts_muxer->video_stream_info;
  ts_muxer->pmt_info.stream[1]         = &ts_muxer->audio_stream_info;
  ts_muxer->pmt_info.descriptor_tag    = 5;
  ts_muxer->pmt_info.descriptor_len    = 4;
  ts_muxer->pmt_info.descriptor        = ts_muxer->pmt_descriptor;
  ts_muxer->pmt_info.descriptor[0]     = 'H';//0x48;
  ts_muxer->pmt_info.descriptor[1]     = 'D';//0x44;
  ts_muxer->pmt_info.descriptor[2]     = 'M';//0x4d;
  ts_muxer->pmt_info.descriptor[3]     = 'V';//0x56;

  __create_pat(&ts_muxer->pat_info, ts_muxer->pat);
  __create_pmt(&ts_muxer->pmt_info, ts_muxer->pmt);

  return ts_muxer;
}

void ts_muxer_destroy(ts_muxer_handle_t handle)
{
  ts_muxer_t *ts_muxer = (ts_muxer_t *)handle;
  if (NULL == ts_muxer) {
    return;
  }

  /* write last ts slice when necessary */
  if (ts_muxer->ts_slice_pos > 0) {
    /* write ts slice to flash or push to OSS... */
    __write_ts_slice(ts_muxer);
  }

  /* append last m3u8 extinf if necessary */
  if (ts_muxer->m3u8_ext_inf_latest_idx != ts_muxer->ts_slice_latest_idx) {
    /* try build m3u8 header if user exit when first slice donot generated already */
    uint64_t pts = ts_muxer->audio_pts > ts_muxer->video_pts ? ts_muxer->audio_pts : ts_muxer->video_pts;
    __build_m3u8_header(ts_muxer, pts);
    __append_m3u8_extinf(ts_muxer, ts_muxer->ts_slice_file_name, pts);
  }

  /* append m3u8 endlist tag if necessary */
  if ((!ts_muxer->config.gen_m3u8_file_for_every_ts_slice && ts_muxer->m3u8_pos > 0) ||
      (ts_muxer->config.gen_m3u8_file_for_every_ts_slice && ts_muxer->ts_slice_pos > 0)) {
    __append_m3u8_endlist(ts_muxer);
    __write_m3u8(ts_muxer);
  }

  /* free m3u8 */
  if (ts_muxer->m3u8) {
    free(ts_muxer->m3u8);
    ts_muxer->m3u8 = NULL;
  }

  /* free ts_slice */
  if (ts_muxer->ts_slice) {
    free(ts_muxer->ts_slice);
    ts_muxer->ts_slice = NULL;
  }

  /* free ts_muxer */
  free(ts_muxer);
}