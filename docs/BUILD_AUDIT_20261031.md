# JZ08 OpenWrt: подтверждённый офлайн-аудит полной сборки (31.10.2026)

> **NOT FLASHABLE.** Проверены результаты компиляции и **полная распаковка реального SquashFS** в изолированной среде CI. Это **не** доказательство загрузки на JZ08, совместимости с OEM GPT или безопасности аппаратного запуска. Никаких прошиваемых бинарников и OEM/NV/IMEI здесь нет.

## Запуски и доказательства (UTC)

| Проверка | Run | Commit | Результат |
|---|---|---|---|
| JZ08 development kernel/OpenWrt | [#41171227189](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41171227189) | `55efa93216aa496a62c77693aa7ec2aff52f3796` | **success**, 31.10.2026 06:21:09 |
| Source checks | [#41171269165](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41171269165) | `0069ca523564b406a8bc6fef504d3591c0915734` | **success**, 31.10.2026 05:06:59, 33 теста |
| Pinned upstream audit | [#41171227206](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41171227206) | `55efa93216aa496a62c77693aa7ec2aff52f3796` | **success**, 31.10.2026 05:06:21 |

Источник: [диагностический архив CI #13032842194](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41171227189/artifacts/13032842194), **37 176 байт**, SHA-256 ZIP:
`629899e4c470e0669457ee6b920356b1cd89669404f2a7fe5326e626a5895a3f`.
Архив **фактически скачан, распакован и проверен**: ZIP CRC OK, все 8 файлов прочитаны, JSON разобран, SHA-256 отдельных файлов рассчитаны. В нём **только журналы, JSON и текстовые манифесты**. Срок хранения артефакта до 14.11.2026 (по метаданным GitHub).

## Реальные результаты сборки (из JSON-аудита CI)

| Компонент | Размер | SHA-256 | Проверка |
|---|---:|---|---|
| JZ08 DTB | 49 249 байт | `c0d9137d0c31b10ea3a9544b1d62e2fb6cd777becad29de0ada43c241332b030` | FDT header, `xarkon,jz08-3000-nkv` |
| `boot.img` | 6 324 499 байт | `f8764a1b2a78e9a179293662cc44cdb3cc7d60d365dbc67bfaf2804fdad8d6cc` | Android legacy boot header, payload bounds |
| `system.img` | 9 498 664 байта | `0f03ee7481644786fbb74e9dd3aa8e430e10eb1d9ca6801a98ef243e0897ed5a` | Android Sparse v1.0, SquashFS v4.0, **полная распаковка** |

`system.img`: 2319 sparse-блоков по 4096 байт, 1 RAW chunk, развёрнутый размер **9 498 624 байта**. SquashFS: **1586 inode**, блок **262 144 байта**, `bytes_used=9494264`. Проверка всех полей вернула `failed_checks=[]`, итог JSON `errors=[]`, `status=BUILD_CHECKS_PASS_ONLY`, `hardware_tested=false`, `flash_allowed=false`.

**Реальный контент проверен**, а не только заголовок: `simg2img` + `unsquashfs -strict-errors` успешно извлекли **1127 файлов, 158 каталогов, 300 символьных ссылок, 1 устройство** (сумма = 1586 inode). Подтверждены каталоги `/etc`, `/bin`, `/sbin`, `/usr`. Отчёт `JZ08_ROOTFS_CONTENTS_STATUS.txt` содержит `PASS` и тот же SHA-256 `system.img`. Распакованный образ и извлечённый rootfs удалены с CI runner, в артефакт не включены.

Манифест: **229 строк пакетов**. Присутствуют все **15 обязательных**: `base-files`, `busybox`, `configs-mifi`, `kernel`, `kmod-qcom-rproc-modem`, `kmod-qcom-rproc-wcnss`, `kmod-usb-gadget-ncm`, `kmod-wcn36xx`, `luci`, `luci-base`, `luci-i18n-base-ru`, `modemmanager`, `procd`, `rmtfs`, `uhttpd`. Дополнительно присутствуют `luci-proto-modemmanager`, `wpad-basic-wolfssl`, `wifi-scripts`, `qrtr-utils`. Это **доказательство включения пакетов в сборку, а не их работы на устройстве**. Kconfig содержит 10 предупреждений о зависимостях других feed-пакетов, не помешавших завершению этой сборки.

## Контрольные суммы восьми текстовых файлов архива

| Путь внутри ZIP | SHA-256 |
|---|---|
| `jz08-development.log` | `513e9f245e558a863790fbe3186f9d8c709e709200ac4599cbe0aad696e67b69` |
| `output/JZ08_BUILD_AUDIT.json` | `ae5303f965592de4647992ca2c2d15b71c98385f55773fecd51dce931bc4aeae` |
| `output/JZ08_DEVELOPMENT_BUILD_STATUS.txt` | `a2b19a2baac740ac0f9667e7c037fea926e3318817ec9a870b9047742b280ba8` |
| `output/JZ08_KCONFIG.log.txt` | `3d6e3acd9000dc793d11f6bec311850f6922cccb6dcc19c80561437e11d397c3` |
| `output/JZ08_REQUIRED_CONFIG.txt` | `03981870643fdb3c65f4f043c7b06f840510e43f8e5fc20ee8f935effd968d55` |
| `output/JZ08_ROOTFS_CONTENTS_STATUS.txt` | `3a6a40161d55daa8a1fdeba7e1366b342646d28ae5cc5ce7b079b9a5c08c2af3` |
| `output/JZ08_ROOTFS_CONTENTS_TEST.txt` | `2879248c99d3debb03f29d86ec53054e640d2636b8b6e9fc056adc6491ffdde6` |
| `output/openwrt-msm89xx-msm8916-generic-jz08-3000-nkv.manifest` | `1baa11e9ac2eb8942b8879d21a2ff3590671dd90bb5b3f972cf1b88c54040147` |

## Непреодолённые границы подтверждения

1. `boot.img` имеет **`ramdisk_size=0`**, а параметр загрузки остаётся `root=PARTLABEL=jz08-unconfigured-rootfs`. Поэтому он **не является проверенным RAM-only загрузочным комплектом**, а Linux `/init` на устройстве не подтверждён. Нельзя предлагать его для записи или заявлять готовность к безопасному аппаратному тесту.
2. OEM GPT содержит **27 разделов**, и **p14 = modemst2**. Штатный MF68E `flash.sh` несовместим и опасен. Ни схема установки rootfs, ни стратегия безопасного запуска/возврата для JZ08 не валидированы.
3. DTS прототипный: LCD отключён, GPIO и физический контроллер не определены. Работа LTE/SIM, Wi-Fi/WCNSS, RMTFS, USB gadget, LCD, аккумулятора и кнопок на JZ08 не проверена.
4. Фактические RAM-адреса/загрузка ядра и безопасный независимый маркер выполнения `/init` требуют отдельных аппаратных доказательств. Компиляция и распаковка не могут их заменить.
5. В этой работе **не выполнялись** EDL/fastboot запись, операции с eMMC, публикация бинарных образов или загрузка OEM/NV/IMEI.

**Решение:** офлайн-этап компиляции и проверки содержимого rootfs пройден; аппаратная готовность **НЕ подтверждена**. Продолжать безопасную подготовку без промежуточных испытаний и сохранять `NOT FLASHABLE`.

## Дополнение: проверка реальных ELF-файлов rootfs (31.10.2026, 09:50 UTC)

Новая полная сборка [#41185758066](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41185758066) завершилась **success** на коммите `97cf0d693a6747e50aa879a50622c5fc413f378f`. Диагностический ZIP [#13038851037](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41185758066/artifacts/13038851037) фактически скачан и проверен: 9 файлов, ZIP CRC OK, SHA-256 ZIP `776db577725351d4e5d9ee4529d3034d34b76dbb3e994ba8dd126f3d251193f4`. В архиве нет бинарных образов.

- JZ08 DTB: **49 249 байт**, SHA-256 `c0d9137d0c31b10ea3a9544b1d62e2fb6cd777becad29de0ada43c241332b030`.
- `boot.img`: **6 324 499 байт**, SHA-256 `f8764a1b2a78e9a179293662cc44cdb3cc7d60d365dbc67bfaf2804fdad8d6cc`, `ramdisk_size=0`.
- `system.img`: **9 494 568 байт**, SHA-256 `2e2d476ae6fd557e8b1e8990732e55e4e9e709309eb3946f2dff2c3201e7cd4b`. Android Sparse и SquashFS проверены, все **1586 inode** распакованы.
- `/sbin/init`: ELF64 AArch64, **65 801 байт**, SHA-256 `09f5ddc2e223a3e3f0545d44851905da58c77d8823236247316b3097fef985f3`.
- `/bin/busybox`: ELF64 AArch64, **458 773 байта**, SHA-256 `9920c5818cc7782377738330d36ee638d1d6fa2e6d8e9ff141851c6867ccf0a0`.
- Оба ELF имеют по два `PT_LOAD`, используют `/lib/ld-musl-aarch64.so.1`; наличие интерпретатора внутри извлечённого rootfs проверено. JSON: `status=OFFLINE_USERSPACE_CHECK_PASS_ONLY`, `errors=[]`, `rootfs_executed=false`, `flash_allowed=false`.

**Уточнение проверки русской локализации.** В отчёте новой сборки путь `/www/luci-static/resources/i18n/base.ru.lmo` отсутствует, но это **не доказательство отсутствия русской локализации**: закреплённый LuCI `luci.mk` устанавливает `base.ru.lmo` по адресу `/usr/lib/lua/luci/i18n/base.ru.lmo`. Добавлен отдельный обязательный офлайн-контроль фактического файла, его ненулевого размера и SHA-256 (коммиты `5392a3db`, `b0511b52`). Source checks [#41193160197](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41193160197) успешны; **результат проверки каталога в новом реальном rootfs ещё ожидается** в [#41193151847](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41193151847). До этого наличие русской локализации подтверждено манифестом пакетов, но не отдельным хешем каталога.

Независимый pinned upstream audit [#41185758053](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41185758053) завершён успешно. Предыдущий параллельный development-run [#41185741728](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41185741728) завершился ошибкой оболочки `command not found` на устаревшем коммите `f43cdd83`; дефект переноса строк исправлен последующим `97cf0d69` и повторная полная сборка успешна. Этот старый отказ не следует принимать за дефект rootfs.

**Итог: NOT FLASHABLE, NOT READY FOR HARDWARE RAM-ONLY TEST.** Не подтверждены безопасные адреса RAM/загрузчика, независимый RAM-only initramfs, исполнение `/init` на плате, LCD/GPIO/LTE/Wi-Fi и стратегия восстановления. Ни одна проверка не разрешает запись eMMC.
