// SPDX-License-Identifier: GPL-2.0-only
/*
 * JZ08-3000-NKV 1.0 ST7735S framebuffer integration source
 * Command stream extracted from owner's Qualcomm OEM DTB.
 * Physical LCD compatibility, GPIO, reset, and WLED are UNVERIFIED.
 * Not bound to hardware while DT is disabled.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include "fbtft.h"

#define DRVNAME "fb_jz08_st7735s"

/* Qualcomm mdss-spi-panel binding: wait follows transmission. */
static int init_display(struct fbtft_par *par)
{
    par->fbtftops.reset(par);
    write_reg(par, 0x11);
    mdelay(120); /* OEM post-command delay */
    write_reg(par, 0xB1, 0x05, 0x3A, 0x3A);
    write_reg(par, 0xB2, 0x05, 0x3A, 0x3A);
    write_reg(par, 0xB3, 0x05, 0x3A, 0x3A, 0x05, 0x3A, 0x3A);
    write_reg(par, 0xB4, 0x03);
    write_reg(par, 0xC0, 0x62, 0x02, 0x04);
    write_reg(par, 0xC1, 0xC0);
    write_reg(par, 0xC2, 0x0D, 0x00);
    write_reg(par, 0xC3, 0x8D, 0x6A);
    write_reg(par, 0xC4, 0x8D, 0xEE);
    write_reg(par, 0xC5, 0x12);
    write_reg(par, 0xE0, 0x03, 0x1B, 0x12, 0x11, 0x3F, 0x3A, 0x32, 0x34, 0x2F, 0x2B, 0x30, 0x3A, 0x00, 0x01, 0x02, 0x05);
    write_reg(par, 0xE1, 0x03, 0x1B, 0x12, 0x11, 0x32, 0x2F, 0x2A, 0x2F, 0x2E, 0x2C, 0x35, 0x3F, 0x00, 0x00, 0x01, 0x05);
    write_reg(par, 0x36, 0xC8);
    write_reg(par, 0x3A, 0x05);
    write_reg(par, 0x2A, 0x00, 0x02, 0x00, 0x81);
    write_reg(par, 0x2B, 0x00, 0x03, 0x00, 0x82);
    write_reg(par, 0x29);
    write_reg(par, 0x2C);
    return 0;
}

static void set_addr_win(struct fbtft_par *par, int xs, int ys, int xe, int ye)
{
    xs += 2; xe += 2; ys += 3; ye += 3;
    write_reg(par, 0x2A, xs >> 8, xs & 0xff, xe >> 8, xe & 0xff);
    write_reg(par, 0x2B, ys >> 8, ys & 0xff, ye >> 8, ye & 0xff);
    write_reg(par, 0x2C);
}

static struct fbtft_display display = {
    .regwidth = 8,
    .width = 128,
    .height = 128,
    .bpp = 16,
    .fps = 20,
    .fbtftops = {
        .init_display = init_display,
        .set_addr_win = set_addr_win,
    },
};

FBTFT_REGISTER_DRIVER(DRVNAME, "xarkon,jz08-st7735s", &display);
MODULE_DESCRIPTION("JZ08 ST7735S OEM-init source; hardware unverified");
MODULE_LICENSE("GPL");
