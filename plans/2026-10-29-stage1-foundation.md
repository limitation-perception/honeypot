# Етап 1 — Фундамент проєкту (роль 3: Core і Storage)

Дата: 2026-10-29
Мета: підготувати основу, щоб ролі 1 (honeypot) і 2 (IDS) могли одразу працювати паралельно.

## Що входить в етап

1. Структура каталогів репозиторію
2. `core/event.h/.c` — контракт події між модулями
3. `core/log.h` — простий логер, щоб помилки не губилися
4. `config.h/.c` + `config/honeytrap.conf` — формат і читання конфігу
5. `main.c` — скелет: конфіг, обробка Ctrl+C, коректне завершення
6. `Makefile` — збірка, `make test`, збірка із санітайзерами
7. Тестовий фреймворк (Unity) і перші тести
8. `.gitignore`

Чого в етапі **немає**: черги, корелятора, SQLite, звіту. Це окремі етапи з окремими планами.

## Наявне оточення (перевірено)

- gcc 16.2.1
- `/usr/include/sqlite3.h` і `/usr/include/pcap.h` є, тобто бібліотеки встановлені
- Unity і CMocka не встановлені

## 1. Структура каталогів

Відповідає розділу 6 концепції. Корінь репозиторію `honeypot/` відіграє роль `honeytrap/`.

```
honeypot/
├── src/
│   ├── main.c
│   ├── config.c / config.h
│   ├── core/
│   │   ├── event.c / event.h
│   │   └── log.h
│   ├── honeypot/        # роль 1 (порожній, .gitkeep)
│   ├── ids/             # роль 2 (порожній, .gitkeep)
│   └── storage/         # етапи 3–4
├── tests/
│   ├── unity/           # вендорені файли Unity
│   ├── fixtures/        # тестові конфіги
│   ├── test_event.c
│   └── test_config.c
├── config/honeytrap.conf
├── plans/
├── Makefile
└── .gitignore
```

## 2. `core/event.h` — контракт

Подія передається **за значенням** і має буфери фіксованого розміру. Так немає `malloc` і не виникає питання, хто звільняє пам'ять: черга просто копіює структуру.

```c
typedef enum {
    EV_SOURCE_HONEYPOT,
    EV_SOURCE_IDS
} event_source_t;

typedef enum {
    /* IDS */
    EV_PORT_SCAN,
    EV_SYN_FLOOD,
    EV_ARP_SPOOF,
    /* Honeypot */
    EV_CONNECT,
    EV_LOGIN_ATTEMPT,
    EV_LOGIN_SUCCESS,
    EV_COMMAND,
    EV_DOWNLOAD_ATTEMPT,
    EV_DISCONNECT,
    EV_TYPE_COUNT        /* завжди останній */
} event_type_t;

#define EV_IP_LEN       16   /* "255.255.255.255" + '\0' (лише IPv4) */
#define EV_USER_LEN     64
#define EV_PASS_LEN     64
#define EV_DETAILS_LEN 256   /* команда, URL, опис детектора */

struct event {
    event_type_t   type;
    event_source_t source;
    time_t         timestamp;
    char           src_ip[EV_IP_LEN];
    uint16_t       dst_port;          /* 0, якщо не застосовно */
    uint32_t       session_id;        /* honeypot-сесія, 0 для IDS */
    char           username[EV_USER_LEN];
    char           password[EV_PASS_LEN];
    char           details[EV_DETAILS_LEN];
};
```

Функції в `event.c`:
- `void event_init(struct event *ev, event_type_t type, event_source_t src, const char *src_ip)` обнуляє структуру, ставить час і безпечно копіює IP через `snprintf`.
- `void event_set_str(char *dst, size_t dst_size, const char *src)` — єдине місце для безпечного копіювання рядків (SSOT). Довгі рядки обрізає, гарантує `'\0'`.
- `const char *event_type_name(event_type_t t)` повертає "PORT_SCAN" тощо. На невідомий тип повертає "UNKNOWN", а не падає мовчки.

Що атакер передає в `username`, `password` і `details`, — **недовірені дані**. Подія лише зберігає їх, а екранування робиться при виводі (у SQLite через bind, в HTML через escape).

**Погодити з командою:** список типів подій і розміри буферів. Після погодження `event.h` змінюється лише за згодою всіх.

## 3. `core/log.h`

Мінімальні макроси без окремого .c:
`LOG_INFO(...)`, `LOG_WARN(...)`, `LOG_ERROR(...)` пишуть у `stderr` з часом, рівнем, `__FILE__:__LINE__`.
Так виконується принцип «never silent failure»: кожна помилка має куди йти.

## 4. Конфіг

Формат `config/honeytrap.conf` — простий `key = value`, рядки на `#` є коментарями:

```
# Honeypot
honeypot.port            = 2222
honeypot.login_after     = 3      # впустити після N спроб
honeypot.max_clients     = 32

# IDS
ids.interface            = eth0
ids.pcap_file            =        # якщо задано, читати файл замість інтерфейсу
ids.portscan_ports       = 20     # стільки різних портів...
ids.portscan_window_sec  = 3      # ...за стільки секунд дають PORT_SCAN
ids.synflood_syns        = 100
ids.synflood_window_sec  = 1

# Core / Storage
core.queue_capacity      = 1024
storage.db_path          = honeytrap.db
storage.report_path      = report.html
```

`config.h`: `struct config` з полями, що відповідають ключам, і функції:
- `void config_set_defaults(struct config *cfg)` — **єдине** місце, де визначено значення за замовчуванням.
- `int config_load(const char *path, struct config *cfg)` повертає 0 при успіху, -1 при помилці.

Правила розбору (жодних мовчазних помилок, на все `LOG_ERROR` з номером рядка):
- невідомий ключ дає помилку (так видно опечатки на кшталт `honeypot.prot`);
- рядок без `=` дає помилку;
- число не парситься (`strtol` + перевірка `endptr`/`errno`) або виходить за діапазон (порт 1–65535, решта > 0) — помилка;
- рядок задовгий для буфера — помилка, а не тихе обрізання;
- файл не відкривається — помилка з `strerror(errno)`.

Ключі не згадані у файлі отримують значення за замовчуванням.

Для розбору ключів буде таблиця `{ "ключ", тип, offsetof(поле), min, max }`. Тоді новий ключ додається одним рядком, а не новою гілкою `if`.

**Погодити з командою:** назви ключів для honeypot та IDS.

## 5. `main.c` — скелет

```
honeytrap [-c path/to/honeytrap.conf]    (за замовчуванням config/honeytrap.conf)
```

1. Розбір аргументів через `getopt`.
2. `config_set_defaults` → `config_load`; при помилці вихід з кодом 1.
3. Обробка `SIGINT`/`SIGTERM` через `sigaction`. Обробник лише виставляє `volatile sig_atomic_t g_stop = 1`.
4. Головний цикл чекає `g_stop` (`pause()`). Тут пізніше з'явиться запуск потоків.
5. Завершення: `LOG_INFO("shutting down")`, вихід з кодом 0.

Місця для потоків honeypot/IDS/корелятора позначаються коментарями `/* етап N: ... */`. Порожніх функцій-заглушок не буде.

## 6. Makefile

- `CC = gcc`
- `CFLAGS = -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror -g -Isrc`
- `LDLIBS = -lpthread` (`-lsqlite3` і `-lpcap` додамо, коли з'явиться код, що їх використовує)
- Об'єктні файли в `build/`, бінарник у `build/honeytrap`
- Цілі:
  - `make` / `make all` збирає програму;
  - `make test` збирає й запускає всі `tests/test_*.c`; якщо хоч один тест впав, ненульовий код виходу;
  - `make SAN=1` збирає з `-fsanitize=address,undefined` (для `thread` буде окрема опція, коли з'являться потоки);
  - `make clean`.
- Тести лінкуються з усіма `.o` проєкту, крім `main.o`.

## 7. Тестовий фреймворк — Unity

**Рішення:** вендорити Unity v2.6.1 (3 файли: `unity.c`, `unity.h`, `unity_internals.h`) у `tests/unity/`.
Чому не CMocka: її треба встановлювати кожному учаснику через пакетний менеджер. Unity просто лежить у репозиторії і працює одразу після `git clone`.
Файли завантажуються з офіційного репозиторію `github.com/ThrowTheSwitch/Unity` (тег `v2.6.1`).

Перші тести:

`tests/test_event.c`:
- `event_type_name` повертає правильні імена й "UNKNOWN" для `EV_TYPE_COUNT`;
- `event_set_str` обрізає задовгий рядок і завжди ставить `'\0'`;
- `event_init` ставить тип, джерело, IP й ненульовий час.

`tests/test_config.c` (фікстури в `tests/fixtures/`):
- валідний файл: усі значення прочитано;
- частковий файл: решта береться з defaults;
- невідомий ключ → -1;
- порт `70000` і `abc` → -1;
- рядок без `=` → -1;
- неіснуючий файл → -1;
- коментарі та порожні рядки ігноруються.

## 8. `.gitignore`

`build/`, `*.db`, `report.html`

## Критерії готовності етапу

- `make` збирається без попереджень (`-Werror`).
- `make test`: усі тести зелені.
- `make SAN=1 && build/honeytrap` стартує, читає конфіг, а за Ctrl+C пише "shutting down" і виходить з кодом 0 без звітів санітайзера.
- `build/honeytrap -c tests/fixtures/bad_key.conf` друкує зрозумілу помилку з номером рядка і виходить з кодом 1.

## Наступні етапи (окремі плани)

2. Потокобезпечна черга + тести з кількома потоками
3. SQLite (`storage/db.c`, prepared statements)
4. Корелятор + алерти в консолі
5. Запуск потоків у `main.c`, коректна зупинка всіх потоків
6. HTML-звіт
