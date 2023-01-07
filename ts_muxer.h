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
#ifndef __TS_MUXER_H__
#define __TS_MUXER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef void (* write_func_t)(const char *data, int len, const char *file_name, void *user_data);

typedef enum {
  TS_VIDEO_TYPE_H264 = 0,
  TS_VIDEO_TYPE_JPEG,
  TS_VIDEO_TYPE_CNT,
} ts_video_type_e;

typedef enum {
  TS_AUDIO_TYPE_AAC_LC = 0,
  TS_AUDIO_TYPE_G722_16K,
  TS_AUDIO_TYPE_G722_8K,
  TS_AUDIO_TYPE_OPUS,
  TS_AUDIO_TYPE_G711A,
  TS_AUDIO_TYPE_G711U,
  TS_AUDIO_TYPE_CNT,
} ts_audio_type_e;

typedef struct {
  ts_video_type_e video_type; /* input video type */
  ts_audio_type_e audio_type; /* input audio type */
  uint32_t        ts_slice_second; /* one ts slice length. such as 5,10 ... */
  /** ts slice file name = ts_slice_file_name_prefix_{i}.ts, i = 1,2,3...
   *  m3u8 file name = ts_slice_file_name_prefix.m3u8
   */
  char            ts_slice_file_name_prefix[128];
  write_func_t    write_handler; /* file write handler, such as write data to flash or push to Oss etc */
  bool            gen_m3u8_file_for_every_ts_slice; /* generate m3u8 playlist when every ts slice done */
  bool            enable_aes_cbc_encrypt_with_pkcs7_padding; /* enable aes cbc encrypt */
  uint8_t         aes_cbc_encrypt_key[16];
  void            *user_data;
} ts_muxer_config_t;

typedef void* ts_muxer_handle_t;

/**
 * @brief create ts muxer handle
 *
 * @param config
 * @return ts_muxer_handle_t
 */
ts_muxer_handle_t ts_muxer_create(ts_muxer_config_t *config);

/**
 * @brief feed audio data to ts-muxer, must be aac-lc now
 *
 * @param handle ts-muxer handle
 * @param data aac-lc data
 * @param len aac-lc data length
 * @param timestamp_in_msec aac timestamp
 * @return int 0 for success, -1 for fail
 */
int ts_muxer_feed_audio(ts_muxer_handle_t handle, uint8_t *data, uint32_t len, uint16_t timestamp_in_msec);

/**
 * @brief feed video data to ts-muxer, must be h264 now
 *
 * @param handle ts-muxer handle
 * @param data h264 data
 * @param len h264 data length
 * @param timestamp_in_msec h264 timestamp
 * @param keyframe I frame or not
 * @return int 0 for success, -1 for fail
 */
int ts_muxer_feed_video(ts_muxer_handle_t handle, uint8_t *data, uint32_t len, uint16_t timestamp_in_msec, bool keyframe);

/**
 * @brief finish ts-muxer
 *
 * @param handle ts-muxer handle
 */
void ts_muxer_destroy(ts_muxer_handle_t handle);

#ifdef __cplusplus
}
#endif
#endif
