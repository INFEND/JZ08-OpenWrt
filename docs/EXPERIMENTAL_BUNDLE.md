# JZ08: единый экспериментальный комплект (NOT FLASHABLE)

Этот документ описывает **инженерный ZIP для анализа и подготовки первого
RAM-only испытания**, а не разрешение на прошивку eMMC. GitHub Actions
публикует ZIP только после успешной компиляции и проверок содержимого.

## Состав

- `images/boot.img`: обычный Android boot v0, собранный OpenWrt. Имеет
  **пустой ramdisk** и указывает на несуществующий подтверждённый раздел
  `root=PARTLABEL=jz08-unconfigured-rootfs`. **Не загружает полную систему.**
- `images/system.img`: Android sparse-контейнер с SquashFS OpenWrt.
  Не является проверенным образом для заводского GPT.
- `images/msm8916-generic-jz08-3000-nkv.dtb`: скомпилированный DTB
  именно JZ08, но прототип LCD отключён.
- `images/kernel-from-boot.bin`: извлечённый kernel payload из boot.img.
- `images/initramfs-kernel.bin`: ядро с включённым в сборке initramfs.
- `images/RAM_ONLY_INITRAMFS_CANDIDATE.img`: отдельный Android boot v0
  с ядром/initramfs и параметром `rdinit=/init`, без `root=`.
  **Его фактическая загрузка на JZ08 не подтверждена.**
- `audit/`: пакеты, отчёт компиляции и аудит извлечённого rootfs.
- `MANIFEST.json`, `SHA256SUMS`, `README_FIRST_RU.txt`.

Вне ZIP публикуются SHA-256 самого ZIP и отчёт проверки архива.
При отсутствии любого обязательного элемента или несовпадении SHA-256
задача сборки должна завершиться ошибкой.

## Что проверяется автоматически

1. Существование и размеры всех бинарных компонентов.
2. Android boot header и границы payload; SquashFS/Android sparse.
3. Заголовок FDT и строка совместимости `xarkon,jz08-3000-nkv`.
4. Манифест пакетов: LuCI, русская локализация, ModemManager, rmtfs,
   WCNSS/Wi-Fi, базовые службы.
5. Полная распаковка SquashFS и ELF64/AArch64 для init/BusyBox.
6. Реальный русский каталог LuCI и наличие основных служб в rootfs.
7. ZIP CRC, повторное чтение каждого файла, SHA-256 каждого файла.

## Неподтверждённые аппаратные условия

- Параметры загрузки Linux через конкретную цепочку LK2ND и адреса RAM.
- Фактический запуск `/init` из встроенного initramfs.
- Совместимость GPIO, контроллера LCD, USB, LTE и Wi-Fi.
- Сохранение штатной OEM GPT и доступность обратного восстановления
  при любом будущем испытании записи.

**Запрещено:** использовать образы для записи в eMMC, менять GPT,
загрузчики, модемные/NV-разделы. OEM p14 содержит `modemst2`, не rootfs.
Не запускать скрипты от `generic-mf68e` на JZ08.

Пока нет доказанного безопасного пути RAM-only загрузки, комплект
остаётся **NOT FLASHABLE / HARDWARE UNVERIFIED**. Готовность ZIP к
скачиванию не равна готовности к аппаратному запуску.

[GitHub Actions JZ08 development](../.github/workflows/jz08-development.yml)
