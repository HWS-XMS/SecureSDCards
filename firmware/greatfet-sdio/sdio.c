/*
 * SDIO Host Driver for GreatFET One
 * Provides low-speed SDIO host functionality for protocol analysis
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <drivers/comms.h>
#include <drivers/scu.h>
#include <drivers/platform_clock.h>

/* DWT Cycle Counter registers (Cortex-M4) */
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000UL)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004UL)
#define DEMCR       (*(volatile uint32_t *)0xE000EDFCUL)
#define DEMCR_TRCENA        (1UL << 24)
#define DWT_CTRL_CYCCNTENA  (1UL << 0)

#define CLASS_NUMBER_SELF (0x120)

/* SDIO Base Address */
#define SDIO_BASE 0x40004000UL

/* SDIO Registers */
#define SDIO_CTRL      (*(volatile uint32_t *)(SDIO_BASE + 0x000))
#define SDIO_PWREN     (*(volatile uint32_t *)(SDIO_BASE + 0x004))
#define SDIO_CLKDIV    (*(volatile uint32_t *)(SDIO_BASE + 0x008))
#define SDIO_CLKSRC    (*(volatile uint32_t *)(SDIO_BASE + 0x00C))
#define SDIO_CLKENA    (*(volatile uint32_t *)(SDIO_BASE + 0x010))
#define SDIO_TMOUT     (*(volatile uint32_t *)(SDIO_BASE + 0x014))
#define SDIO_CTYPE     (*(volatile uint32_t *)(SDIO_BASE + 0x018))
#define SDIO_BLKSIZ    (*(volatile uint32_t *)(SDIO_BASE + 0x01C))
#define SDIO_BYTCNT    (*(volatile uint32_t *)(SDIO_BASE + 0x020))
#define SDIO_INTMASK   (*(volatile uint32_t *)(SDIO_BASE + 0x024))
#define SDIO_CMDARG    (*(volatile uint32_t *)(SDIO_BASE + 0x028))
#define SDIO_CMD       (*(volatile uint32_t *)(SDIO_BASE + 0x02C))
#define SDIO_RESP0     (*(volatile uint32_t *)(SDIO_BASE + 0x030))
#define SDIO_RESP1     (*(volatile uint32_t *)(SDIO_BASE + 0x034))
#define SDIO_RESP2     (*(volatile uint32_t *)(SDIO_BASE + 0x038))
#define SDIO_RESP3     (*(volatile uint32_t *)(SDIO_BASE + 0x03C))
#define SDIO_MINTSTS   (*(volatile uint32_t *)(SDIO_BASE + 0x040))
#define SDIO_RINTSTS   (*(volatile uint32_t *)(SDIO_BASE + 0x044))
#define SDIO_STATUS    (*(volatile uint32_t *)(SDIO_BASE + 0x048))
#define SDIO_FIFOTH    (*(volatile uint32_t *)(SDIO_BASE + 0x04C))
#define SDIO_CDETECT   (*(volatile uint32_t *)(SDIO_BASE + 0x050))
#define SDIO_RST_N     (*(volatile uint32_t *)(SDIO_BASE + 0x078))
#define SDIO_BMOD      (*(volatile uint32_t *)(SDIO_BASE + 0x080))
#define SDIO_DATA      (*(volatile uint32_t *)(SDIO_BASE + 0x200))

/* CGU BASE_SDIO_CLK register */
#define CGU_BASE_SDIO_CLK (*(volatile uint32_t *)0x40050068UL)

/* CCU1 CLK_M4_SDIO_CFG register - enables SDIO clock */
#define CCU1_CLK_M4_SDIO_CFG (*(volatile uint32_t *)0x40051C00UL)

/* SCU pin registers for SDIO */
#define SCU_SFSP1_6   (*(volatile uint32_t *)0x40086098UL)
#define SCU_SFSP1_9   (*(volatile uint32_t *)0x400860A4UL)
#define SCU_SFSP1_10  (*(volatile uint32_t *)0x400860A8UL)
#define SCU_SFSP1_11  (*(volatile uint32_t *)0x400860ACUL)
#define SCU_SFSP1_12  (*(volatile uint32_t *)0x400860B0UL)
#define SCU_SFSCLK2   (*(volatile uint32_t *)0x40086C08UL)

/* SDIO_CTRL bits */
#define SDIO_CTRL_CONTROLLER_RESET  (1UL << 0)
#define SDIO_CTRL_FIFO_RESET        (1UL << 1)
#define SDIO_CTRL_DMA_RESET         (1UL << 2)
#define SDIO_CTRL_INT_ENABLE        (1UL << 4)

/* SDIO_CMD bits */
#define SDIO_CMD_START_CMD          (1UL << 31)
#define SDIO_CMD_UPDATE_CLK_ONLY    (1UL << 21)
#define SDIO_CMD_SEND_INIT          (1UL << 15)
#define SDIO_CMD_STOP_ABORT         (1UL << 14)
#define SDIO_CMD_WAIT_PRVDATA       (1UL << 13)
#define SDIO_CMD_SEND_AUTO_STOP     (1UL << 12)
#define SDIO_CMD_TRANSFER_MODE      (1UL << 11)
#define SDIO_CMD_READ_WRITE         (1UL << 10)
#define SDIO_CMD_DATA_EXPECTED      (1UL << 9)
#define SDIO_CMD_CHECK_RESP_CRC     (1UL << 8)
#define SDIO_CMD_RESPONSE_LENGTH    (1UL << 7)
#define SDIO_CMD_RESPONSE_EXPECT    (1UL << 6)

/* SDIO_RINTSTS bits */
#define SDIO_INT_CD     (1UL << 0)
#define SDIO_INT_RE     (1UL << 1)
#define SDIO_INT_CDONE  (1UL << 2)
#define SDIO_INT_DTO    (1UL << 3)
#define SDIO_INT_TXDR   (1UL << 4)
#define SDIO_INT_RXDR   (1UL << 5)
#define SDIO_INT_RCRC   (1UL << 6)
#define SDIO_INT_DCRC   (1UL << 7)
#define SDIO_INT_RTO    (1UL << 8)
#define SDIO_INT_DRTO   (1UL << 9)
#define SDIO_INT_HTO    (1UL << 10)
#define SDIO_INT_FRUN   (1UL << 11)
#define SDIO_INT_HLE    (1UL << 12)
#define SDIO_INT_SBE    (1UL << 13)
#define SDIO_INT_EBE    (1UL << 15)

/* SDIO_STATUS bits */
#define SDIO_STATUS_FIFO_EMPTY  (1UL << 2)
#define SDIO_STATUS_FIFO_FULL   (1UL << 3)
#define SDIO_STATUS_DATA_BUSY   (1UL << 9)

/* SCU pin mode for SDIO function 7 with fast slew, input buffer, pull-up enabled */
#define SCU_SDIO_MODE  (7UL | (1UL << 5) | (1UL << 6))

static uint32_t sdio_clock_divider = 255;
static bool sdio_initialized = false;
static bool sdio_4bit_mode = false;

/* ============================================================================
 * Configurable Trigger System
 * ============================================================================
 * Trigger fires once when armed and conditions match, then auto-disarms.
 *
 * Conditions (all enabled conditions must match):
 *   - cmd_match: Trigger on specific SD command (e.g., 24 for CMD24/write)
 *   - addr_match: Trigger on specific block address
 *   - ins_match: Trigger on specific APDU INS byte in FSI command block
 *
 * Usage from Python:
 *   1. Configure trigger: sdio.trigger_config(cmd=24, addr=0x350580, ins=0x30)
 *   2. Arm trigger: sdio.trigger_arm()
 *   3. Execute operations - trigger fires on match
 *   4. Check if fired: sdio.trigger_status()
 */

/* GPIO trigger pin - GPIO0[2] = P1_15 = J1_P28 */
#define GPIO_PORT0_DIR  (*(volatile uint32_t *)0x400F6000UL)
#define GPIO_PORT0_SET  (*(volatile uint32_t *)0x400F6200UL)
#define GPIO_PORT0_CLR  (*(volatile uint32_t *)0x400F6280UL)
#define TRIGGER_PIN     (1UL << 2)  /* GPIO0[2] */

/* SCU for P1_15: function 0 = GPIO0[2] - base 0x40086080 + 15*4 = 0x400860BC */
#define SCU_SFSP1_15    (*(volatile uint32_t *)0x400860BCUL)

/* VDD_EN power control pin - GPIO1[1] = P1_8 = J1_P18 */
#define GPIO_PORT1_DIR  (*(volatile uint32_t *)0x400F6004UL)
#define GPIO_PORT1_SET  (*(volatile uint32_t *)0x400F6204UL)
#define GPIO_PORT1_CLR  (*(volatile uint32_t *)0x400F6284UL)
#define VDD_EN_PIN      (1UL << 1)  /* GPIO1[1] */

/* SCU for P1_8: function 0 = GPIO1[1] - base 0x40086080 + 8*4 = 0x400860A0 */
#define SCU_SFSP1_8     (*(volatile uint32_t *)0x400860A0UL)

/* Trigger state */
static struct {
    bool armed;
    bool fired;
    bool initialized;

    /* Match conditions - 0xFFFFFFFF means "don't care" / disabled */
    uint32_t cmd_match;     /* SD command index to match (e.g., 24) */
    uint32_t addr_match;    /* Block address to match */
    uint32_t ins_match;     /* APDU INS byte to match (0-255, or 0xFFFFFFFF=disabled) */
} trigger = {
    .armed = false,
    .fired = false,
    .initialized = false,
    .cmd_match = 0xFFFFFFFF,
    .addr_match = 0xFFFFFFFF,
    .ins_match = 0xFFFFFFFF,
};

/* Power control state */
static struct {
    bool initialized;
    bool enabled;
} power_ctrl = {
    .initialized = false,
    .enabled = false,
};

/* Cycle counter state - stores absolute DWT_CYCCNT timestamps */
static struct {
    bool initialized;
    uint32_t last_write_start;
    uint32_t last_write_end;
    uint32_t last_read_start;
    uint32_t last_read_end;
} cycle_counter = {
    .initialized = false,
    .last_write_start = 0,
    .last_write_end = 0,
    .last_read_start = 0,
    .last_read_end = 0,
};

static void power_ctrl_init(void)
{
    if (!power_ctrl.initialized) {
        /* Configure P1_8 as GPIO function 0, output */
        SCU_SFSP1_8 = 0;  /* Function 0, no pull-up/down */
        GPIO_PORT1_DIR |= VDD_EN_PIN;  /* Output */
        GPIO_PORT1_CLR = VDD_EN_PIN;   /* Start with power OFF (safe default) */
        power_ctrl.initialized = true;
        power_ctrl.enabled = false;
    }
}

static void power_ctrl_set(bool enable)
{
    power_ctrl_init();
    if (enable) {
        GPIO_PORT1_SET = VDD_EN_PIN;
        power_ctrl.enabled = true;
    } else {
        GPIO_PORT1_CLR = VDD_EN_PIN;
        power_ctrl.enabled = false;
    }
}

static void cycle_counter_init(void)
{
    if (!cycle_counter.initialized) {
        /* Enable DWT cycle counter */
        DEMCR |= DEMCR_TRCENA;
        DWT_CYCCNT = 0;
        DWT_CTRL |= DWT_CTRL_CYCCNTENA;
        cycle_counter.initialized = true;
    }
}

static void trigger_init(void)
{
    if (!trigger.initialized) {
        /* Configure P1_15 as GPIO function 0, output */
        SCU_SFSP1_15 = 0;  /* Function 0, no pull-up/down */
        GPIO_PORT0_DIR |= TRIGGER_PIN;  /* Output */
        GPIO_PORT0_CLR = TRIGGER_PIN;   /* Start low */
        trigger.initialized = true;
    }
}

/* Check conditions and fire trigger if armed and matching */
static inline void trigger_check(uint8_t cmd, uint32_t addr, const uint8_t *data)
{
    if (!trigger.armed)
        return;

    /* Check command match */
    if (trigger.cmd_match != 0xFFFFFFFF && cmd != trigger.cmd_match)
        return;

    /* Check address match */
    if (trigger.addr_match != 0xFFFFFFFF && addr != trigger.addr_match)
        return;

    /* Check APDU INS byte match (INS is at offset 0x25 in FSI block: identifier[32] + dir + flags + len[2] + CLA + INS) */
    if (trigger.ins_match != 0xFFFFFFFF && data != NULL) {
        uint8_t ins = data[0x25];  /* CLA at 0x24, INS at 0x25 */
        if (ins != (uint8_t)trigger.ins_match)
            return;
    }

    /* All conditions match - fire! */
    GPIO_PORT0_SET = TRIGGER_PIN;
    /* Delay for pulse visibility - ~100ns at 204MHz (20 nops) */
    __asm volatile ("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                    "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n");
    GPIO_PORT0_CLR = TRIGGER_PIN;

    trigger.fired = true;
    trigger.armed = false;  /* Auto-disarm */
}

/* Configure SDIO pins */
static void sdio_configure_pins(void)
{
    /* Configure P1 pins for SDIO function (function 7)
     * P1_6  = SD_CMD
     * P1_9  = SD_DAT0
     * P1_10 = SD_DAT1
     * P1_11 = SD_DAT2
     * P1_12 = SD_DAT3
     * CLK2 = SD_CLK (function 4)
     */
    SCU_SFSP1_6  = SCU_SDIO_MODE;  /* CMD */
    SCU_SFSP1_9  = SCU_SDIO_MODE;  /* DAT0 */
    SCU_SFSP1_10 = SCU_SDIO_MODE;  /* DAT1 */
    SCU_SFSP1_11 = SCU_SDIO_MODE;  /* DAT2 */
    SCU_SFSP1_12 = SCU_SDIO_MODE;  /* DAT3 */
    /* CLK2 (J2_P12): function 4 for SD_CLK, fast slew, no pull */
    SCU_SFSCLK2  = (4UL | (1UL << 4) | (1UL << 5));
}

/* Update clock settings */
static int sdio_update_clock(void)
{
    SDIO_CMD = SDIO_CMD_START_CMD | SDIO_CMD_UPDATE_CLK_ONLY | SDIO_CMD_WAIT_PRVDATA;

    uint32_t timeout = 100000;
    while ((SDIO_CMD & SDIO_CMD_START_CMD) && --timeout)
        ;

    return (timeout == 0) ? -ETIMEDOUT : 0;
}

/* Set clock divider */
static int sdio_set_clock(uint8_t divider)
{
    /* Disable clock */
    SDIO_CLKENA = 0;
    sdio_update_clock();

    /* Set divider */
    SDIO_CLKDIV = divider;
    sdio_update_clock();

    /* Enable clock */
    SDIO_CLKENA = 1;
    sdio_update_clock();

    sdio_clock_divider = divider;
    return 0;
}

/* Wait for command to complete */
static int sdio_wait_cmd_complete(void)
{
    uint32_t timeout = 1000000;

    while (timeout--) {
        uint32_t ints = SDIO_RINTSTS;
        if (ints & SDIO_INT_CDONE) {
            SDIO_RINTSTS = SDIO_INT_CDONE;
            return 0;
        }
        if (ints & SDIO_INT_RTO) {
            SDIO_RINTSTS = SDIO_INT_RTO;
            return -ETIMEDOUT;
        }
        if (ints & SDIO_INT_RE) {
            SDIO_RINTSTS = SDIO_INT_RE;
            return -EIO;
        }
    }
    return -ETIMEDOUT;
}

/* Wait for data transfer to complete */
static int sdio_wait_data_complete(void)
{
    uint32_t timeout = 5000000;

    while (timeout--) {
        uint32_t ints = SDIO_RINTSTS;
        if (ints & SDIO_INT_DTO) {
            SDIO_RINTSTS = SDIO_INT_DTO;
            return 0;
        }
        if (ints & SDIO_INT_DRTO) {
            SDIO_RINTSTS = SDIO_INT_DRTO;
            return -ETIMEDOUT;
        }
        if (ints & SDIO_INT_DCRC) {
            SDIO_RINTSTS = SDIO_INT_DCRC;
            return -EIO;
        }
        if (ints & SDIO_INT_SBE) {
            SDIO_RINTSTS = SDIO_INT_SBE;
            return -EIO;
        }
        if (ints & SDIO_INT_EBE) {
            SDIO_RINTSTS = SDIO_INT_EBE;
            return -EIO;
        }
    }
    return -ETIMEDOUT;
}

/* Read data from FIFO after a read command */
static int sdio_read_fifo(uint8_t *buffer, uint32_t length)
{
    uint32_t words = (length + 3) / 4;
    uint32_t *buf32 = (uint32_t *)buffer;
    uint32_t timeout;

    for (uint32_t i = 0; i < words; i++) {
        timeout = 1000000;
        /* Wait for data available in FIFO */
        while ((SDIO_STATUS & SDIO_STATUS_FIFO_EMPTY) && --timeout)
            ;
        if (timeout == 0)
            return -ETIMEDOUT;

        buf32[i] = SDIO_DATA;
    }
    return 0;
}

/* Send command with data read phase */
static int sdio_cmd_read_data(uint8_t cmd_index, uint32_t argument, uint8_t *buffer, uint32_t length)
{
    /* Store absolute timestamp at start */
    cycle_counter.last_read_start = DWT_CYCCNT;

    /* Reset FIFO with timeout */
    SDIO_CTRL |= SDIO_CTRL_FIFO_RESET;
    for (volatile int i = 0; i < 10000 && (SDIO_CTRL & SDIO_CTRL_FIFO_RESET); i++)
        ;

    /* Clear pending interrupts */
    SDIO_RINTSTS = 0xFFFFFFFF;

    /* Set byte count and block size */
    SDIO_BYTCNT = length;
    SDIO_BLKSIZ = length;

    /* Set argument */
    SDIO_CMDARG = argument;

    /* Build command: data expected, read from card */
    uint32_t cmd = SDIO_CMD_START_CMD | (cmd_index & 0x3F) |
                   SDIO_CMD_RESPONSE_EXPECT | SDIO_CMD_CHECK_RESP_CRC |
                   SDIO_CMD_DATA_EXPECTED | SDIO_CMD_WAIT_PRVDATA;

    /* Issue command */
    SDIO_CMD = cmd;

    /* Wait for command complete */
    int ret = sdio_wait_cmd_complete();
    if (ret != 0)
        return ret;

    /* Read data from FIFO */
    ret = sdio_read_fifo(buffer, length);
    if (ret != 0)
        return ret;

    /* Wait for data transfer complete */
    ret = sdio_wait_data_complete();

    /* Store absolute timestamp at end */
    cycle_counter.last_read_end = DWT_CYCCNT;

    return ret;
}

/* Send command with data write phase */
static int sdio_cmd_write_data(uint8_t cmd_index, uint32_t argument, const uint8_t *buffer, uint32_t length)
{
    /* Check trigger BEFORE any SD bus activity */
    trigger_check(cmd_index, argument, buffer);

    /* Store absolute timestamp at start */
    cycle_counter.last_write_start = DWT_CYCCNT;

    /* Reset FIFO with timeout */
    SDIO_CTRL |= SDIO_CTRL_FIFO_RESET;
    for (volatile int i = 0; i < 10000 && (SDIO_CTRL & SDIO_CTRL_FIFO_RESET); i++)
        ;

    /* Clear pending interrupts */
    SDIO_RINTSTS = 0xFFFFFFFF;

    /* Set byte count and block size */
    SDIO_BYTCNT = length;
    SDIO_BLKSIZ = length;

    uint32_t words = (length + 3) / 4;
    const uint32_t *buf32 = (const uint32_t *)buffer;
    uint32_t words_written = 0;

    /* Set argument */
    SDIO_CMDARG = argument;

    /* Build command: data expected, write to card */
    uint32_t cmd = SDIO_CMD_START_CMD | (cmd_index & 0x3F) |
                   SDIO_CMD_RESPONSE_EXPECT | SDIO_CMD_CHECK_RESP_CRC |
                   SDIO_CMD_DATA_EXPECTED | SDIO_CMD_READ_WRITE | SDIO_CMD_WAIT_PRVDATA;

    /* Issue command */
    SDIO_CMD = cmd;

    /* Wait for command complete */
    int ret = sdio_wait_cmd_complete();
    if (ret != 0)
        return ret;

    /* Write data to FIFO while monitoring for errors */
    uint32_t timeout = 10000000;
    while (words_written < words) {
        uint32_t ints = SDIO_RINTSTS;

        /* Check for errors */
        if (ints & (SDIO_INT_DCRC | SDIO_INT_SBE | SDIO_INT_EBE | SDIO_INT_DRTO)) {
            return -EIO;
        }

        /* Write data when FIFO has space */
        if (!(SDIO_STATUS & SDIO_STATUS_FIFO_FULL)) {
            SDIO_DATA = buf32[words_written++];
            timeout = 10000000;
        } else if (--timeout == 0) {
            return -ETIMEDOUT;
        }
    }

    /* Wait for data transfer complete */
    ret = sdio_wait_data_complete();
    if (ret != 0)
        return ret;

    /* Wait for card to finish programming (DAT0 busy) */
    uint32_t busy_timeout = 10000000;
    while ((SDIO_STATUS & SDIO_STATUS_DATA_BUSY) && --busy_timeout)
        ;
    if (busy_timeout == 0)
        return -ETIMEDOUT;

    /* Store absolute timestamp at end */
    cycle_counter.last_write_end = DWT_CYCCNT;

    return 0;
}

/* Initialize SDIO peripheral */
static int sdio_init(uint8_t clock_divider)
{
    /* Enable clock to SDIO peripheral - use PLL1 as source, auto-block enabled */
    CGU_BASE_SDIO_CLK = (0x09UL << 24) | (1UL << 11);

    /* Enable SDIO peripheral clock in CCU1 */
    CCU1_CLK_M4_SDIO_CFG = 1;

    /* Reset SDIO controller with timeout */
    SDIO_CTRL = SDIO_CTRL_CONTROLLER_RESET | SDIO_CTRL_FIFO_RESET | SDIO_CTRL_DMA_RESET;
    for (volatile int i = 0; i < 100000 && (SDIO_CTRL & (SDIO_CTRL_CONTROLLER_RESET | SDIO_CTRL_FIFO_RESET | SDIO_CTRL_DMA_RESET)); i++)
        ;

    /* Configure pins */
    sdio_configure_pins();

    /* Set timeout values */
    SDIO_TMOUT = 0xFFFFFFFF;

    /* Set FIFO threshold: RX trigger at 1 word, TX trigger at 8 words, DMA burst 1 */
    SDIO_FIFOTH = (0 << 28) | (7 << 16) | (0 << 0);

    /* Clear all interrupts */
    SDIO_RINTSTS = 0xFFFFFFFF;

    /* Power on card */
    SDIO_PWREN = 1;

    /* Set clock */
    sdio_set_clock(clock_divider);

    /* 1-bit mode by default */
    SDIO_CTYPE = 0;
    sdio_4bit_mode = false;

    /* Set block size */
    SDIO_BLKSIZ = 512;

    /* Enable interrupts */
    SDIO_CTRL |= SDIO_CTRL_INT_ENABLE;

    /* Initialize cycle counter */
    cycle_counter_init();

    sdio_initialized = true;
    return 0;
}

/* === Verb handlers === */

static int sdio_verb_init(struct command_transaction *trans)
{
    uint8_t clock_divider = comms_argument_parse_uint8_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    int ret = sdio_init(clock_divider);
    comms_response_add_int32_t(trans, ret);

    return 0;
}

static int sdio_verb_set_clock(struct command_transaction *trans)
{
    uint8_t divider = comms_argument_parse_uint8_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    int ret = sdio_set_clock(divider);
    comms_response_add_int32_t(trans, ret);

    return 0;
}

static int sdio_verb_set_bus_width(struct command_transaction *trans)
{
    uint8_t width = comms_argument_parse_uint8_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    if (width == 4) {
        SDIO_CTYPE = 1;
        sdio_4bit_mode = true;
    } else {
        SDIO_CTYPE = 0;
        sdio_4bit_mode = false;
    }

    comms_response_add_int32_t(trans, 0);
    return 0;
}

static int sdio_verb_send_command(struct command_transaction *trans)
{
    uint8_t cmd_index = comms_argument_parse_uint8_t(trans);
    uint32_t argument = comms_argument_parse_uint32_t(trans);
    uint32_t flags = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    if (!sdio_initialized) {
        comms_response_add_int32_t(trans, -ENODEV);
        comms_response_add_uint32_t(trans, 0);
        comms_response_add_uint32_t(trans, 0);
        comms_response_add_uint32_t(trans, 0);
        comms_response_add_uint32_t(trans, 0);
        return 0;
    }

    /* Clear pending interrupts */
    SDIO_RINTSTS = 0xFFFFFFFF;

    /* Set argument */
    SDIO_CMDARG = argument;

    /* Build command register value */
    uint32_t cmd = SDIO_CMD_START_CMD | (cmd_index & 0x3F);

    if (flags & SDIO_CMD_RESPONSE_EXPECT)
        cmd |= SDIO_CMD_RESPONSE_EXPECT;
    if (flags & SDIO_CMD_RESPONSE_LENGTH)
        cmd |= SDIO_CMD_RESPONSE_LENGTH;
    if (flags & SDIO_CMD_CHECK_RESP_CRC)
        cmd |= SDIO_CMD_CHECK_RESP_CRC;
    if (flags & SDIO_CMD_DATA_EXPECTED)
        cmd |= SDIO_CMD_DATA_EXPECTED;
    if (flags & SDIO_CMD_READ_WRITE)
        cmd |= SDIO_CMD_READ_WRITE;

    /* Send initialization clocks for CMD0 */
    if (cmd_index == 0)
        cmd |= SDIO_CMD_SEND_INIT;

    /* Issue command */
    SDIO_CMD = cmd;

    /* Wait for completion */
    int ret = sdio_wait_cmd_complete();

    /* Return results */
    comms_response_add_int32_t(trans, ret);
    comms_response_add_uint32_t(trans, SDIO_RESP0);
    comms_response_add_uint32_t(trans, SDIO_RESP1);
    comms_response_add_uint32_t(trans, SDIO_RESP2);
    comms_response_add_uint32_t(trans, SDIO_RESP3);

    return 0;
}

static int sdio_verb_get_status(struct command_transaction *trans)
{
    comms_response_add_uint32_t(trans, SDIO_STATUS);
    comms_response_add_uint32_t(trans, SDIO_RINTSTS);
    comms_response_add_uint32_t(trans, SDIO_CDETECT);
    comms_response_add_uint8_t(trans, sdio_initialized ? 1 : 0);
    comms_response_add_uint8_t(trans, sdio_4bit_mode ? 4 : 1);
    comms_response_add_uint8_t(trans, (uint8_t)sdio_clock_divider);

    return 0;
}

/* Read single block (CMD17) */
static int sdio_verb_read_block(struct command_transaction *trans)
{
    uint32_t address = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    static uint8_t block_buffer[512];

    if (!sdio_initialized) {
        comms_response_add_int32_t(trans, -ENODEV);
        comms_response_add_raw(trans, block_buffer, 512);
        return 0;
    }
    int ret = sdio_cmd_read_data(17, address, block_buffer, 512);

    comms_response_add_int32_t(trans, ret);
    /* Always return 512 bytes - on error, buffer contains garbage but Python expects it */
    comms_response_add_raw(trans, block_buffer, 512);

    return 0;
}

/* Write single block (CMD24) */
static int sdio_verb_write_block(struct command_transaction *trans)
{
    uint32_t address = comms_argument_parse_uint32_t(trans);
    uint32_t data_length = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    if (!sdio_initialized) {
        comms_response_add_int32_t(trans, -ENODEV);
        return 0;
    }

    if (data_length != 512) {
        comms_response_add_int32_t(trans, -EINVAL);
        return 0;
    }

    uint32_t actual_length;
    uint8_t *block_buffer = comms_argument_read_buffer(trans, 512, &actual_length);

    if (!comms_transaction_okay(trans) || !block_buffer) {
        return EBADMSG;
    }

    int ret = sdio_cmd_write_data(24, address, block_buffer, 512);
    comms_response_add_int32_t(trans, ret);

    return 0;
}

/* CMD56 read - General command with data read */
static int sdio_verb_cmd56_read(struct command_transaction *trans)
{
    uint32_t argument = comms_argument_parse_uint32_t(trans);
    uint32_t length = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    if (!sdio_initialized) {
        comms_response_add_int32_t(trans, -ENODEV);
        return 0;
    }

    if (length > 512) {
        comms_response_add_int32_t(trans, -EINVAL);
        return 0;
    }

    static uint8_t data_buffer[512];
    memset(data_buffer, 0, sizeof(data_buffer));

    /* CMD56 with bit 0 = 1 means read from card */
    int ret = sdio_cmd_read_data(56, argument | 1, data_buffer, length);

    comms_response_add_int32_t(trans, ret);
    comms_response_add_uint32_t(trans, SDIO_RESP0);
    if (ret == 0) {
        comms_response_add_raw(trans, data_buffer, length);
    }

    return 0;
}

/* CMD56 write - General command with data write */
static int sdio_verb_cmd56_write(struct command_transaction *trans)
{
    uint32_t argument = comms_argument_parse_uint32_t(trans);
    uint32_t length = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    if (!sdio_initialized) {
        comms_response_add_int32_t(trans, -ENODEV);
        return 0;
    }

    if (length > 512) {
        comms_response_add_int32_t(trans, -EINVAL);
        return 0;
    }

    uint32_t actual_length;
    uint8_t *data_buffer = comms_argument_read_buffer(trans, length, &actual_length);

    if (!comms_transaction_okay(trans) || !data_buffer) {
        return EBADMSG;
    }

    /* CMD56 with bit 0 = 0 means write to card */
    int ret = sdio_cmd_write_data(56, argument & ~1, data_buffer, length);

    comms_response_add_int32_t(trans, ret);
    comms_response_add_uint32_t(trans, SDIO_RESP0);

    return 0;
}

/* === Trigger verb handlers === */

static int sdio_verb_trigger_config(struct command_transaction *trans)
{
    uint32_t cmd_match = comms_argument_parse_uint32_t(trans);
    uint32_t addr_match = comms_argument_parse_uint32_t(trans);
    uint32_t ins_match = comms_argument_parse_uint32_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    trigger_init();
    trigger.cmd_match = cmd_match;
    trigger.addr_match = addr_match;
    trigger.ins_match = ins_match;

    comms_response_add_int32_t(trans, 0);
    return 0;
}

static int sdio_verb_trigger_arm(struct command_transaction *trans)
{
    trigger.armed = true;
    trigger.fired = false;

    comms_response_add_int32_t(trans, 0);
    return 0;
}

static int sdio_verb_trigger_status(struct command_transaction *trans)
{
    comms_response_add_uint8_t(trans, trigger.armed ? 1 : 0);
    comms_response_add_uint8_t(trans, trigger.fired ? 1 : 0);
    comms_response_add_uint32_t(trans, trigger.cmd_match);
    comms_response_add_uint32_t(trans, trigger.addr_match);
    comms_response_add_uint32_t(trans, trigger.ins_match);

    return 0;
}

/* === Power control verb handlers === */

static int sdio_verb_power_set(struct command_transaction *trans)
{
    uint8_t enable = comms_argument_parse_uint8_t(trans);

    if (!comms_transaction_okay(trans)) {
        return EBADMSG;
    }

    power_ctrl_set(enable ? true : false);
    comms_response_add_int32_t(trans, 0);
    return 0;
}

static int sdio_verb_power_status(struct command_transaction *trans)
{
    power_ctrl_init();
    comms_response_add_uint8_t(trans, power_ctrl.enabled ? 1 : 0);
    return 0;
}

/* === Cycle counter verb handlers === */

static int sdio_verb_get_cycle_count(struct command_transaction *trans)
{
    cycle_counter_init();
    comms_response_add_uint32_t(trans, DWT_CYCCNT);
    return 0;
}

static int sdio_verb_get_last_cycles(struct command_transaction *trans)
{
    comms_response_add_uint32_t(trans, cycle_counter.last_write_start);
    comms_response_add_uint32_t(trans, cycle_counter.last_write_end);
    comms_response_add_uint32_t(trans, cycle_counter.last_read_start);
    comms_response_add_uint32_t(trans, cycle_counter.last_read_end);
    return 0;
}

/* Verb dispatch table */
static struct comms_verb sdio_verbs[] = {
    { .name = "init", .handler = sdio_verb_init,
      .in_signature = "<B", .out_signature = "<i",
      .doc = "Initialize SDIO with clock divider (0-255)" },

    { .name = "set_clock", .handler = sdio_verb_set_clock,
      .in_signature = "<B", .out_signature = "<i",
      .doc = "Set clock divider" },

    { .name = "set_bus_width", .handler = sdio_verb_set_bus_width,
      .in_signature = "<B", .out_signature = "<i",
      .doc = "Set bus width (1 or 4)" },

    { .name = "send_command", .handler = sdio_verb_send_command,
      .in_signature = "<BII", .out_signature = "<iIIII",
      .doc = "Send command (index, arg, flags) -> (status, resp0-3)" },

    { .name = "get_status", .handler = sdio_verb_get_status,
      .in_signature = "", .out_signature = "<IIIBBB",
      .doc = "Get SDIO status" },

    { .name = "read_block", .handler = sdio_verb_read_block,
      .in_signature = "<I", .out_signature = "<i*X",
      .doc = "Read 512-byte block (CMD17)" },

    { .name = "write_block", .handler = sdio_verb_write_block,
      .in_signature = "<II*X", .out_signature = "<i",
      .doc = "Write 512-byte block (CMD24)" },

    { .name = "cmd56_read", .handler = sdio_verb_cmd56_read,
      .in_signature = "<II", .out_signature = "<iI*X",
      .doc = "CMD56 read (arg, len) -> (status, resp, data)" },

    { .name = "cmd56_write", .handler = sdio_verb_cmd56_write,
      .in_signature = "<II*X", .out_signature = "<iI",
      .doc = "CMD56 write (arg, len, data) -> (status, resp)" },

    { .name = "trigger_config", .handler = sdio_verb_trigger_config,
      .in_signature = "<III", .out_signature = "<i",
      .doc = "Configure trigger (cmd, addr, ins) - use 0xFFFFFFFF to disable condition" },

    { .name = "trigger_arm", .handler = sdio_verb_trigger_arm,
      .in_signature = "", .out_signature = "<i",
      .doc = "Arm trigger - fires once on match, then auto-disarms" },

    { .name = "trigger_status", .handler = sdio_verb_trigger_status,
      .in_signature = "", .out_signature = "<BBIII",
      .doc = "Get trigger status (armed, fired, cmd, addr, ins)" },

    { .name = "power_set", .handler = sdio_verb_power_set,
      .in_signature = "<B", .out_signature = "<i",
      .doc = "Set DUT power (0=off, 1=on) - controls TPS7A2033 EN via J1_P18" },

    { .name = "power_status", .handler = sdio_verb_power_status,
      .in_signature = "", .out_signature = "<B",
      .doc = "Get DUT power status (0=off, 1=on)" },

    { .name = "get_cycle_count", .handler = sdio_verb_get_cycle_count,
      .in_signature = "", .out_signature = "<I",
      .doc = "Get current absolute DWT cycle counter (at 204 MHz)" },

    { .name = "get_last_cycles", .handler = sdio_verb_get_last_cycles,
      .in_signature = "", .out_signature = "<IIII",
      .doc = "Get absolute timestamps: write_start, write_end, read_start, read_end" },

    {}
};

COMMS_DEFINE_SIMPLE_CLASS(sdio, CLASS_NUMBER_SELF, "sdio", sdio_verbs,
    "SDIO host controller for protocol analysis");
