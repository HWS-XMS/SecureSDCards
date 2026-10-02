/*
 * SDIO Host Driver for GreatFET One
 */

#ifndef __GREATFET_SDIO_H__
#define __GREATFET_SDIO_H__

#include <stdint.h>
#include <stdbool.h>

/* Command flags for sdio_send_cmd */
#define SDIO_FLAG_RESPONSE_EXPECT    (1 << 6)
#define SDIO_FLAG_RESPONSE_LONG      (1 << 7)
#define SDIO_FLAG_CHECK_CRC          (1 << 8)
#define SDIO_FLAG_DATA_EXPECTED      (1 << 9)
#define SDIO_FLAG_WRITE              (1 << 10)

/* Common SD Commands */
#define SD_CMD0_GO_IDLE_STATE        0
#define SD_CMD2_ALL_SEND_CID         2
#define SD_CMD3_SEND_RELATIVE_ADDR   3
#define SD_CMD7_SELECT_CARD          7
#define SD_CMD8_SEND_IF_COND         8
#define SD_CMD9_SEND_CSD             9
#define SD_CMD10_SEND_CID            10
#define SD_CMD12_STOP_TRANSMISSION   12
#define SD_CMD13_SEND_STATUS         13
#define SD_CMD16_SET_BLOCKLEN        16
#define SD_CMD17_READ_SINGLE_BLOCK   17
#define SD_CMD18_READ_MULTIPLE_BLOCK 18
#define SD_CMD24_WRITE_BLOCK         24
#define SD_CMD25_WRITE_MULTIPLE_BLOCK 25
#define SD_CMD55_APP_CMD             55
#define SD_CMD58_READ_OCR            58

/* Application-specific commands (after CMD55) */
#define SD_ACMD6_SET_BUS_WIDTH       6
#define SD_ACMD41_SD_SEND_OP_COND    41

#endif /* __GREATFET_SDIO_H__ */
