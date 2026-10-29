# MagnumGO MCP

Неофициальный прямой API-клиент MagnumGO и локальный MCP-сервер. Контракты восстановлены из Android-приложения **4.3.15**. Для работы телефон и ADB не нужны.

## Реализовано

14 MCP-инструментов:

- Сессия: `auth_status`, `start_login`, `profile_status`, `refresh_session`.
- Каталог: `categories`, `search`, `list_products`, `suggest`, `product`.
- Доставка: `delivery_context`, `merchant_delivery`.
- Корзина: `read_cart`, `set_cart_quantity`, `remove_cart_item`.

Поиск возвращает одну страницу до 20 товаров. `price_kzt` — цена в тенге, `price_raw` — исходное число API. Запись в корзину задаёт абсолютное количество и требует свежую `revision` и `operation_id`. После неопределённого исхода нужна проверка корзины; журнал повторов действует до перезапуска процесса. Оформление заказа и оплата не реализованы.

## Установка на Raspberry Pi

Нужны Linux, Python 3.11+ и `systemd-creds --user` (systemd 256+). Ниже `/opt/magnum-go-mcp` и `<user>@pi-host` — примеры, замените их своими значениями.

```sh
cd /opt/magnum-go-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp magnum.config.example.json magnum.config.json
```

## Конфигурация

`magnum.config.json` рядом с модулями:

```json
{"request_interval_seconds": 0.5}
```

`MAGNUM_CONFIG` задаёт другой путь к файлу. `MAGNUM_REQUEST_INTERVAL_SECONDS` переопределяет интервал. Интервал — положительное конечное число. Локальный конфиг не следует добавлять в Git. После изменения перезапустите MCP.

Запросы последовательны; интервал по умолчанию — 0,5 секунды между началами. Ограничитель общий для процессов одного Linux-пользователя; используйте для них одинаковые настройки. Чтения каталога кэшируются, корзина — нет. Автоповторов, фонового опроса и автопагинации нет; HTTP 429 включает общий cooldown.

## Как работает с Dot

MCP выполняется на Малинке от одного Linux-пользователя и общается через **stdio**. MCP-клиент на подключённом компьютере запускает его напрямую или через SSH; пример — [mcp-config.example.json](mcp-config.example.json):

```sh
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes '<user>@pi-host' \
  /opt/magnum-go-mcp/.venv/bin/python /opt/magnum-go-mcp/magnum_mcp.py
```

Dot может поручать работу этому подключённому компьютеру. Облачный Dot сам по себе не получает доступ к частному адресу Малинки; сервер ещё нужно подключить к используемому MCP-клиенту. Автозапуск и глобальная регистрация MCP этим проектом не устанавливаются. Инструкция для ассистента — [DOT-INSTRUCTIONS.txt](DOT-INSTRUCTIONS.txt).

Обычный сценарий: `auth_status` → `delivery_context` → `search`/`product` → `read_cart`. Используйте `platform_id` из текущего контекста доставки и `itemId` из найденного товара. Корзину меняйте по явному запросу пользователя с учётом `measureUnit.step`.

## Авторизация

`start_login` выдаёт одноразовую страницу на `127.0.0.1:8765`. Номер и SMS-код пользователь вводит в браузере; они не передаются через MCP. Для удалённого браузера нужен отдельный туннель:

```sh
ssh -N -L 127.0.0.1:8765:127.0.0.1:8765 '<user>@pi-host'
```

Сессия хранится через `systemd-creds --user --with-key=host` в `$XDG_STATE_HOME/magnum-go/session.cred` или `~/.local/state/magnum-go/session.cred` (каталог 0700, файл 0600). MCP под тем же пользователем использует сохранённую авторизацию; отдельный вход для Dot не нужен. Host key не защищает от root или копии всей системы вместе с ключом.

Обновление сессии явное: `refresh_session` один раз, затем проверка статуса. При отказе потребуется новый вход. Полный ответ об ошибке доступен на странице с маскировкой секретов.

## Проверка

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Весь реализованный функционал проверен на Raspberry Pi, включая авторизацию, обновление сессии, каталог, доставку и изменение корзины через MCP.

