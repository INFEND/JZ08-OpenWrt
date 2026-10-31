# XARKON JZ08 OpenWrt

**Экспериментальный порт OpenWrt для LCD MiFi с платой JZ08-3000-NKV 1.0 (Qualcomm MSM8916).**

> **НЕ ГОТОВАЯ ПРОШИВКА. НЕ ПРОШИВАТЬ ОБРАЗЫ ИЗ ЭТОГО РЕПОЗИТОРИЯ.** Аппаратная загрузка Linux/OpenWrt и работа модема, Wi-Fi и LCD ещё не доказаны. Автоматические проверки не заменяют тест на реальном роутере.

## Что уже подтверждено

- Плата `JZ08-3000-NKV 1.0`, SoC `msm8916`; заводская Android 4.4.4 (`JZ_MIFI_LCD_COM_20260615`).
- eMMC: **3 909 091 328 байт**, 7 634 944 секторов по 512; **27 OEM GPT-разделов**.
- Полный локальный дамп получен через EDL 05c6:9008; SHA-256: `2271764802356a14b8d51ba0950abc9e1af3634e260d488cdd9128c3e4fb34bc`.
- OEM `boot` p22 16 MiB, `system` p23 800 MiB, `userdata` p27 ≈2.48 GiB; **p14 = modemst2**.
- LK2ND 0.5 реально запущен и отвечал через Fastboot `18d1:d00d`.
- Linux ARM64 6.12 RAMBoot передан через `fastboot boot`, но его фактический старт не подтверждён.
- EDL запись и последующее SHA-256 чтение OEM recovery p26 успешно выполнены в предыдущей диагностике; проверка восстановления *всего* накопителя не проводилась.
- В заводском Device Tree встречаются ST7735S и NV3023A, SPI4. Фактический установленный контроллер LCD не подтверждён.

## Почему нельзя прошивать MF68E как есть

У `generic-mf68e` другая GPT (15 разделов) и `root=/dev/mmcblk0p14`. На JZ08 раздел p14 — **modemst2**, содержащий данные модема. Штатный `flash.sh` MF68E пишет чужую GPT и bootloader-компоненты. **Категорически запрещено** исполнять его на JZ08.

## Как организован проект

- `board/` — декларативный паспорт платы и прототип DTS с выключенным LCD.
- `ci/` — локальные проверки и контроль ограничений.
- `.github/workflows/` — CI; никаких EDL/fastboot записей.
- `docs/` — порядок инженерной адаптации и критерии готовности.

Основа для изучения: [rabbits0209/msm8916-xiaoxun-openwrt](https://github.com/rabbits0209/msm8916-xiaoxun-openwrt) @ `c2e2dd5afc6ec4e8be55cfc952a1fce042e681c4`; OpenWrt @ `46ab9f3f1c0e6ac2a17efa5a3f34e466a0c2d4e0`. Исходный релиз пользователя: [hkfuertes/msm8916-openwrt v1.0.11](https://github.com/hkfuertes/msm8916-openwrt/releases/tag/v1.0.11), SHA-256 архива MF68E `ff2d24be69b6a2a6b9985dff68ae24745ac72760ea64ff31b15429d7b02dcaa4`.

## Статус

| Область | Статус |
|---|---|
| OEM GPT и полный дамп | подтверждены по диагностике |
| EDL read/write p26 | подтверждены по диагностике |
| LK2ND Fastboot | подтверждён по диагностике |
| Linux init / rootfs | **не подтверждены** |
| Драйверы LCD, Wi-Fi, LTE | **не подтверждены** |
| RAM-only кандидат Android boot | **генерируется CI, аппаратная загрузка не подтверждена** |
| Готовая прошивка | **отсутствует** |

Разработку ведём без публикации полного eMMC, IMEI, NV, калибровок и других уникальных данных. Подробности: [docs/PORTING.md](docs/PORTING.md).

Для запуска проверок: `python3 -m unittest discover -s tests -v`.

**Важно:** открытые исходники LCD v29 частично перенесены в [drivers/lcd](drivers/lcd) и проверяются статическими тестами. Полный ZIP `XARKON_JZ08_GPT_ASTRA_HANDOFF_20261030.zip`, экспериментальные бинарники, заводской дамп и конфиденциальные отчёты **не опубликованы** здесь. Компиляция upstream не доказывает работоспособность прошивки JZ08. Текущий процесс сборки: [GitHub Actions](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions); незавершённые задачи: [Issues](https://github.com/ANTIFERMENT/JZ08-OpenWrt/issues).

## Автоматически опубликованный инструмент S24 Ultra

Для проверки имеющегося заводского дампа без EDL и без перепрошивки:
**[JZ08_SAFE_BACKUP_AUDIT.zip](https://github.com/ANTIFERMENT/JZ08-OpenWrt/releases/download/safe-preflight/JZ08_SAFE_BACKUP_AUDIT.zip)**.
Это исполняемый Python ZIP для Termux, опубликованный автоматической
[GitHub Actions проверкой](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/workflows/safe-preflight.yml).
Он валидирует обе GPT, 27 OEM-разделов, размер, защиту p14 и полный SHA-256,
затем сохраняет один ZIP-отчёт в Download. **Он не пишет в роутер.**
[Команды запуска на S24](docs/S24_INSTALL.md).

В GitHub Actions настроена сборка единого архива инженерных бинарных артефактов
с отдельным RAM-only кандидатом на основе initramfs. До успешной публикации
и проверки реального ZIP комплект не считается готовым. **Его загрузка на JZ08 не
подтверждена; он не предназначен для записи в eMMC.** Условия и состав:
[Экспериментальный комплект](docs/EXPERIMENTAL_BUNDLE.md).

Текущие проверенные аппаратные факты и недоказанные этапы:
[Журнал доказательств 30.10.2026](docs/EVIDENCE_20261030.md).
