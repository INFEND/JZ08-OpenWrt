XARKON JZ08 FASTBOOT PROOF v32

ОСНОВНАЯ ЗАДАЧА: отличить заводской Fastboot ABOOT от LK2ND по ответам и оригинальному журналу LK2ND.
Испытание через раздел RECOVERY p26; никакой полной прошивки OpenWrt.

Запуск без распаковки:
python /sdcard/Download/XARKON_JZ08_LK2ND_FASTBOOT_PROOF_v32.zip --cycle

Важно: --cycle ФИЗИЧЕСКИ переписывает раздел recovery p26, затем проверяет его, перезапускает в recovery, слушает USB и вызывает ТОЛЬКО НЕЗАПИСЫВАЮЩИЕ команды Fastboot (devices, getvar, oem log, get_staged).
Для возвращения заводского Recovery ПОСЛЕ ручного запуска Android:
python /sdcard/Download/XARKON_JZ08_LK2ND_FASTBOOT_PROOF_v32.zip --restore-factory

Только проверка уже находящегося в Fastboot устройства БЕЗ какой-либо записи:
python /sdcard/Download/XARKON_JZ08_LK2ND_FASTBOOT_PROOF_v32.zip --probe-fastboot

ОШИБКИ показываются по-русски, отладка и результат сохраняются в /sdcard/Download/XARKON_JZ08_REPORTS/XARKON_JZ08_LK2ND_PROOF_V32_*.zip.

Если штатный ABOOT блокирует образ или отсутствует USB Fastboot, команда ОБ ЭТОМ СКАЖЕТ, а не выдаст ложный успех. Запреты: не пишет boot, aboot, system, modem, GPT. Никакого fastboot boot/reboot/erase/flash.

Риск: заводской ABOOT может не принять экспериментальный p26, устройство может зависнуть. Откат возможен только если возврат в Android/EDL доступен. Сам тест НЕ доказывает, что Linux/OpenWrt сможет загрузиться.
