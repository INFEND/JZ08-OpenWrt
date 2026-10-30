# Samsung S24 Ultra: требования к будущему установщику

Это не исполняемая инструкция прошивки: совместимая система пока отсутствует.

- Samsung S24 Ultra, Magisk root, Termux, USB OTG.
- Один ZIP с Python zipapp в Download; запуск без ручной распаковки.
- Безопасная диагностика без лишних вопросов; опасные изменения только после реального подтверждения совместимости.
- Автоидентификация через проверенные USB PID, SoC, GPT, eMMC sector geometry.
- Проверить исходный локальный backup SHA256; не загружать его в Интернет.
- Перед записью нужен протестированный rollback, защищённые NV и полный план разделов.
- После записи обязательно проверять readback, загрузку, локализацию LuCI, Wi-Fi, LTE, USB, LCD и персистентность.
- Единый ZIP-отчёт в Download с реальными статусами и числами.

Сейчас установки нет. Все потенциально записывающие команды запрещены.

## Проверка заводского дампа, доступна уже сейчас

Добавлен автономный **только читающий** инструмент
[`tools/jz08_backup_audit.py`](../tools/jz08_backup_audit.py).
Он проверяет полные SHA-256, геометрию 3 909 091 328 байт,
защитную MBR, CRC32 обоих заголовков GPT и обеих таблиц,
27 разделов и обязательные имена p14/p22/p23/p26/p27.

Запускается на S24 Ultra в Termux. Для скачивания только проверяющего
скрипта (никакой записи в MiFi):

```bash
pkg install -y python curl
curl -fL --retry 3 --output /storage/emulated/0/Download/jz08_backup_audit.py \
  https://raw.githubusercontent.com/ANTIFERMENT/JZ08-OpenWrt/main/tools/jz08_backup_audit.py
python /storage/emulated/0/Download/jz08_backup_audit.py \
  --backup /storage/emulated/0/Download/XARKON_MIFI_SAFE_COPY/flash_emmc_20261028_082457_verified.bin
```

Создаётся один ZIP-отчёт `/storage/emulated/0/Download/XARKON_JZ08_REPORTS/`.
Не копировать в публичный GitHub сам образ eMMC. Проверка дампа
**не подтверждает, что Linux, драйверы, радиомодем или LCD работают**.
Если файл бэкапа отсутствует, статус будет FAIL, а не ложный PASS.
Скрипт вообще не обращается к USB/EDL/ADB и ничего не прошивает.

### Готовый ZIP без распаковки (автоматический GitHub Release)

[**JZ08_SAFE_BACKUP_AUDIT.zip**](https://github.com/ANTIFERMENT/JZ08-OpenWrt/releases/download/safe-preflight/JZ08_SAFE_BACKUP_AUDIT.zip)
публикуется автоматически после успешных тестов, вместе с
[контрольной суммой SHA-256](https://github.com/ANTIFERMENT/JZ08-OpenWrt/releases/download/safe-preflight/JZ08_SAFE_BACKUP_AUDIT.sha256).
Не содержит прошивки и не подключается к роутеру.

```bash
pkg install -y python curl
curl -fL --retry 3 -o /storage/emulated/0/Download/JZ08_SAFE_BACKUP_AUDIT.zip \
  https://github.com/ANTIFERMENT/JZ08-OpenWrt/releases/download/safe-preflight/JZ08_SAFE_BACKUP_AUDIT.zip
curl -fL --retry 3 -o /storage/emulated/0/Download/JZ08_SAFE_BACKUP_AUDIT.sha256 \
  https://github.com/ANTIFERMENT/JZ08-OpenWrt/releases/download/safe-preflight/JZ08_SAFE_BACKUP_AUDIT.sha256
(cd /storage/emulated/0/Download && sha256sum -c JZ08_SAFE_BACKUP_AUDIT.sha256) &&
python /storage/emulated/0/Download/JZ08_SAFE_BACKUP_AUDIT.zip \
  --backup /storage/emulated/0/Download/XARKON_MIFI_SAFE_COPY/flash_emmc_20261028_082457_verified.bin
```

Устанавливаемых прошивок здесь **нет**; данный ZIP предназначен только для проверки ранее сделанного дампа.
