/* SPDX-License-Identifier: GPL-2.0-only */
/* NV3023A JZ08, INCOMPLETE and DISABLED until GPIO and power verified */
#include <dt-bindings/gpio/gpio.h>
&blsp_spi4 {
    status = "disabled";
    panel@0 {
        compatible = "xarkon,jz08-nv3023a";
        reg = <0>;
        spi-max-frequency = <16000000>;
        status = "disabled";
        /* Must determine reset-gpios, dc-gpios, backlight and power */
    };
};
