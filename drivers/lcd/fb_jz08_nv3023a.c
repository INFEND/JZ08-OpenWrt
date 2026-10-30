// SPDX-License-Identifier: GPL-2.0-only
/*
 * JZ08-3000-NKV 1.0 NV3023A framebuffer integration source
 * Command stream extracted from owner's Qualcomm OEM DTB.
 * Physical LCD compatibility, GPIO, reset, and WLED are UNVERIFIED.
 * Not bound to hardware while DT is disabled.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include "fbtft.h"

#define DRVNAME "fb_jz08_nv3023a"

static int init_display(struct fbtft_par *par)
{
    par->fbtftops.reset(par);
    write_reg(par, 0xFF, 0xA5);
    write_reg(par, 0x3E, 0x09);
    write_reg(par, 0x3A, 0x65);
    write_reg(par, 0x82, 0x00);
    write_reg(par, 0x63, 0x0F);
    write_reg(par, 0x64, 0x0F);
    write_reg(par, 0xB4, 0x24);
    write_reg(par, 0xB5, 0x30);
    write_reg(par, 0x83, 0x03);
    write_reg(par, 0x86, 0x04);
    write_reg(par, 0x87, 0x16);
    write_reg(par, 0x88, 0x0F);
    write_reg(par, 0x89, 0x2D);
    write_reg(par, 0x93, 0x63);
    write_reg(par, 0x96, 0x81);
    write_reg(par, 0xC3, 0x10);
    write_reg(par, 0xE6, 0x00);
    write_reg(par, 0x99, 0x01);
    write_reg(par, 0x70, 0x07);
    write_reg(par, 0x71, 0x15);
    write_reg(par, 0x72, 0x18);
    write_reg(par, 0x73, 0x10);
    write_reg(par, 0x74, 0x17);
    write_reg(par, 0x75, 0x1B);
    write_reg(par, 0x76, 0x38);
    write_reg(par, 0x77, 0x0A);
    write_reg(par, 0x78, 0x04);
    write_reg(par, 0x79, 0x3C);
    write_reg(par, 0x7A, 0x06);
    write_reg(par, 0x7B, 0x0C);
    write_reg(par, 0x7C, 0x11);
    write_reg(par, 0x7D, 0x0B);
    write_reg(par, 0x7E, 0x08);
    write_reg(par, 0x7F, 0x12);
    write_reg(par, 0xA0, 0x0D);
    write_reg(par, 0xA1, 0x3E);
    write_reg(par, 0xA2, 0x0B);
    write_reg(par, 0xA3, 0x0F);
    write_reg(par, 0xA4, 0x0A);
    write_reg(par, 0xA5, 0x23);
    write_reg(par, 0xA6, 0x48);
    write_reg(par, 0xA7, 0x04);
    write_reg(par, 0xA8, 0x05);
    write_reg(par, 0xA9, 0x45);
    write_reg(par, 0xAA, 0x0A);
    write_reg(par, 0xAB, 0x12);
    write_reg(par, 0xAC, 0x0D);
    write_reg(par, 0xAD, 0x06);
    write_reg(par, 0xAE, 0x3E);
    write_reg(par, 0xAF, 0x12);
    write_reg(par, 0xFF, 0x00);
    write_reg(par, 0x11);
    mdelay(120); /* OEM post-command delay */
    write_reg(par, 0x36, 0x88);
    write_reg(par, 0x21);
    write_reg(par, 0x2A, 0x00, 0x00, 0x00, 0x7F);
    write_reg(par, 0x2B, 0x00, 0x00, 0x00, 0x7F);
    write_reg(par, 0x29);
    mdelay(10); /* OEM post-command delay */
    write_reg(par, 0x2C);
    return 0;
}

static void set_addr_win(struct fbtft_par *par, int xs, int ys, int xe, int ye)
{
    write_reg(par, 0x2A, xs >> 8, xs & 0xff, xe >> 8, xe & 0xff);
    write_reg(par, 0x2B, ys >> 8, ys & 0xff, ye >> 8, ye & 0xff);
    write_reg(par, 0x2C);
}

static struct fbtft_display display = {
    .regwidth = 8,
    .width = 128,
    .height = 128,
    .bpp = 16,
    .fps = 27,
    .fbtftops = {
        .init_display = init_display,
        .set_addr_win = set_addr_win,
    },
};

FBTFT_REGISTER_DRIVER(DRVNAME, "xarkon,jz08-nv3023a", &display);
MODULE_DESCRIPTION("JZ08 NV3023A OEM-init source; hardware unverified");
MODULE_LICENSE("GPL");
