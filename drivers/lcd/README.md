# LCD source prototypes from XARKON v29
Both panel drivers contain OEM initialization command streams for ST7735S and NV3023A. These source files are NOT automatically linked into any firmware or enabled in JZ08 Device Tree. Original project had two distinct candidates; only one can be physically present, which remains to be confirmed.

The commands and timing come from OEM DTB decoding, not electrical tests. For now keep disabled DT nodes. The integration into target Linux 6.12 is **not verified**; kernel APIs and Kconfig must be tested before enabling.

Upstream reference: XARKON_JZ08_M68E_LCD_INTEGRATION_v29.zip.
