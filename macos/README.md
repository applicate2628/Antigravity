# Antigravity Unlocker для macOS

Порт для macOS основан на работе [Fuheshka](https://github.com/Fuheshka/Antigravity-Unlocker), исходный проект — [confeden/Antigravity](https://github.com/confeden/Antigravity). Интегрированная версия использует общий код Windows/WSL и требует отдельной проверки на целевой системе; сборка сама по себе не подтверждает работу патча или модели.

## Локальная сборка

Скрипт `macos/build_app.sh` создаёт универсальный пакет для Apple Silicon и Intel. По умолчанию проверка локального ключа остаётся включённой. Для личной сборки с локальным входом без ключа используйте `macos/build_app.sh --personal`; это не меняет проверку группового ключа или серверную авторизацию.

Не запускайте скрипты установки или изменения системных настроек, не проверив их действие и назначение. Если система не доверяет приложению, используйте штатные настройки macOS и не отключайте системную защиту.

## Авторы

- Оригинальный проект и сетевой релей: Brent, [@nova_txt](https://t.me/nova_txt), [confeden/Antigravity](https://github.com/confeden/Antigravity).
- Портирование на macOS и упаковка: [Fuheshka](https://github.com/Fuheshka/Antigravity-Unlocker), [@fuheshka](https://t.me/fuheshka).
