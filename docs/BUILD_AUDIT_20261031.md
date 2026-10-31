# JZ08 development build: проверенные результаты 31.10.2026

> **NOT FLASHABLE.** Этот документ фиксирует результаты компиляции и проверки файлов, а не готовность устройства к прошивке или доказательство загрузки OpenWrt на плате.

## Проверенные запуски GitHub Actions

| Проверка | Run | Коммит | Результат (UTC) |
|---|---|---|---|
| Development kernel/OpenWrt | [#41144764814](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41144764814) | `1dcf0592f4` | **success**, 2026-10-31 00:35:59 |
| Source checks | [#41144764713](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41144764713) | `1dcf0592f4` | **success**, 2026-10-30 23:29:32 |
| Source checks, дополнительный регрессионный тест | [#41144797947](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41144797947) | `d5c400059a` | **success**, 2026-10-30 23:29:55 |
| Pinned upstream audit | [#41055012365](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41055012365) | более ранняя ревизия | **success**, 2026-10-30; не повторялся для этого коммита |

Последний development job завершился успешно, включая шаг загрузки **только журналов и текстовых манифестов**. [Артефакт с отчётами](https://github.com/ANTIFERMENT/JZ08-OpenWrt/actions/runs/41144764814/artifacts/13023635222), 36 233 байта, содержит 6 файлов, хранится 14 дней. Бинарные образы не опубликованы.

## Фактические результаты аудита сборки

Из JSON-аудита, выведенного в job log (файлы существовали на временном CI runner):

| Объект | Размер | SHA-256 | Проверка |
|---|---:|---|---|
| JZ08 DTB | 49 249 байт | `c0d9137d0c31b10ea3a9544b1d62e2fb6cd777becad29de0ada43c241332b030` | FDT magic и compatible `xarkon,jz08-3000-nkv` |
| `*-squashfs-boot.img` | 6 324 499 байт | `f8764a1b2a78e9a179293662cc44cdb3cc7d60d365dbc67bfaf2804fdad8d6cc` | Android boot header |
| `*-squashfs-system.img` | 9 494 568 байт | `048ed41793816b652f6523e2e63d563e65ffd7ba4ea875097f98df0fd14bff58` | Android Sparse v1.0, структурная проверка и встроенный SquashFS v4.0 |

`system.img`: 2 318 блоков по 4096 байт, 1 sparse chunk, развёрнутый размер 9 494 528 байт. Внутренний SquashFS: 1 586 inode, размер блока 262 144 байта, `bytes_used=9494188`, `failed_checks=[]`, `valid=true`. Итоговый аудит: `status=BUILD_CHECKS_PASS_ONLY`, `errors=[]`, `hardware_tested=false`, `flash_allowed=false`.

В package manifest обнаружены все 15 обязательных пакетов: `base-files`, `busybox`, `configs-mifi`, `kernel`, `kmod-qcom-rproc-modem`, `kmod-qcom-rproc-wcnss`, `kmod-usb-gadget-ncm`, `kmod-wcn36xx`, `luci`, `luci-base`, `luci-i18n-base-ru`, `modemmanager`, `procd`, `rmtfs`, `uhttpd`. Наличие в манифесте не доказывает работоспособность пакетов на физическом устройстве.

## Что пока нельзя считать готовым

1. JZ08 DTS остаётся **прототипом** с отключённым SPI LCD; конкретные GPIO, LCD-контроллер, питание и аппаратная совместимость не подтверждены.
2. Boot profile намеренно использует `root=PARTLABEL=jz08-unconfigured-rootfs`, чтобы исключить опасную загрузку с неверного OEM-раздела. Реальная схема rootfs на заводской GPT не подготовлена. Наличие `boot.img` **не означает**, что он безопасен или способен запустить рабочую систему.
3. Не доказаны исполнение Linux `/init`, загрузка OpenWrt, работа LTE/SIM, Wi-Fi, USB, LCD и сохранение конфигурации на JZ08.
4. Ни `boot.img`, ни `system.img` не прошли аппаратную проверку. Полная процедура безопасного теста без записи в eMMC пока не валидирована; автоматический допуск к прошивке запрещён.
5. Не публиковать OEM eMMC/NV/IMEI/калибровки и не применять MF68E GPT/`flash.sh`. Особенно важно: OEM p14 = `modemst2`.

**Следующий этап:** продолжать статическую проверку и подготовку документированного безопасного RAM-only испытания. Запрашивать аппаратный тест только после отдельного подтверждения пригодности полного комплекта для такого теста. `NOT FLASHABLE` сохраняется.
