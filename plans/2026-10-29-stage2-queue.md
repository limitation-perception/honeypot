# Етап 2 — Потокобезпечна черга подій

Дата: 2026-10-29
Гілка: `core/queue`
Мета: дати honeypot та IDS спосіб передавати події коректору з різних потоків так, щоб жодна подія не губилася і програма могла коректно зупинитися.

## Що входить в етап

1. `src/core/queue.h/.c` — обмежена черга (кільцевий буфер) на `pthread_mutex` + `pthread_cond`
2. `tests/test_queue.c` — тести однопотокові та багатопотокові
3. Makefile: збірка з ThreadSanitizer
4. Стиль коду як в етапі 1: без коментарів

Чого **немає**: інтеграції в `main.c`. Черга без споживача там не потрібна, тож підключимо її в етапі 5 разом із потоками.

## Як черга виглядає ззовні

```
 honeypot-потік 1 ─┐
 honeypot-потік 2 ─┼── queue_push() ──► [ кільцевий буфер ] ──► queue_pop() ── коректор
 IDS-потік        ─┘                         ▲
                                   queue_close() з main за Ctrl+C
```

Кілька потоків додають події (producers), один потік їх забирає (consumer).

## API (`queue.h`)

```c
struct event_queue;

struct event_queue *queue_create(size_t capacity);
void queue_destroy(struct event_queue *q);

int  queue_push(struct event_queue *q, const struct event *ev);
int  queue_pop(struct event_queue *q, struct event *out);
void queue_close(struct event_queue *q);
```

- `queue_create`: ємність береться з `cfg.core_queue_capacity`. Якщо `capacity == 0` або не вдався `malloc` чи `pthread_*_init`, функція пише `LOG_ERROR` і повертає `NULL`.
- `queue_push` копіює подію в чергу. **Якщо черга повна, чекає**, поки з'явиться місце. Повертає `0`, а якщо черга закрита, `-1`.
- `queue_pop` забирає найстарішу подію. **Якщо черга порожня, чекає.** Повертає `0`, а `-1` лише тоді, коли черга закрита **і** порожня.
- `queue_close` будить усі потоки, які чекають. Після закриття `push` одразу повертає `-1`, а `pop` спершу віддає все, що лишилося, і тільки потім `-1`. Так за Ctrl+C жодна вже прийнята подія не губиться.
- `queue_destroy` викликається лише тоді, коли всі потоки вже завершилися (`join`).

Структура `struct event_queue` прихована в `queue.c`: інші модулі можуть працювати з чергою лише через API.

## Рішення: що робити, коли черга повна

**Обрано: `push` чекає (блокується).**

| Варіант | Плюси | Мінуси |
|---|---|---|
| **Чекати** (обрано) | Жодна подія не губиться; найпростіший код | Якщо коректор повільний, producers гальмують |
| Відкидати й рахувати | Producers ніколи не чекають | Події губляться, потрібні лічильник і попередження |

Чому блокування підходить:
- IDS кладе в чергу не кожен пакет, а лише **результат** детектора (одна подія `PORT_SCAN` на скан). Тому навіть під час SYN-flood подій мало.
- Honeypot-потік, що чекає, просто трохи пізніше відповість атакеру. Це не страшно.
- З ємністю 1024 черга на практиці не заповнюватиметься.

Якщо на демо це стане проблемою, `push` легко замінити на версію з відкиданням, API від цього не зміниться.

## Реалізація (`queue.c`)

```c
struct event_queue {
    struct event   *items;
    size_t          capacity;
    size_t          head;
    size_t          count;
    bool            closed;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
};
```

- Індекс для запису: `(head + count) % capacity`, для читання: `head`.
- Очікування завжди в циклі `while (умова) pthread_cond_wait(...)`, бо можливі spurious wakeups.
- `push` → `pthread_cond_signal(&not_empty)`, `pop` → `pthread_cond_signal(&not_full)`.
- `close` → `closed = true` + `pthread_cond_broadcast` для обох умов.

**Помилки pthread:** помилки `init` обробляються так, як описано вище, а ресурси, створені до збою, звільняються. Помилки `lock`/`unlock`/`wait` можливі лише через баг у програмі, тому їх перевіряє маленька функція `check_pthread()`: вона пише `LOG_ERROR` і викликає `abort()`. Помилка ніколи не проходить непоміченою, а код не обростає `if`-ами.

## Makefile

Зараз є `make SAN=1` (address + undefined). Заміна:

- `make SAN=address` — AddressSanitizer + UBSan, вихід у `build/address/`
- `make SAN=thread` — ThreadSanitizer, вихід у `build/thread/`. Він ловить гонки даних, і для черги це головна перевірка.

ASan і TSan не можна вмикати разом, тому це дві окремі збірки. `SAN=1` прибираємо.

## Тести (`tests/test_queue.c`)

Однопотокові:
- `create(0)` повертає `NULL`;
- FIFO: push 1, 2, 3 → pop повертає 1, 2, 3;
- перехід через кінець буфера: ємність 3, по черзі 10 push/pop, порядок не порушується;
- `close` на порожній черзі: `pop` одразу повертає `-1`;
- `close` з подіями: push 2, close → pop, pop повертають `0`, третій pop `-1`;
- push після close → `-1`.

Багатопотокові:
- **Стрес:** 4 producers × 10 000 подій, ємність 16 (щоб `push` справді часто чекав), 1 consumer. Кожна подія має унікальний `session_id`. Перевірка: отримано рівно 40 000, кожну рівно один раз, а порядок подій від кожного producer збережено.
- **close будить consumer:** consumer чекає на порожній черзі, main робить `close`, consumer завершується з `-1`.
- **close будить producer:** черга ємністю 1 заповнена, producer чекає в `push`, main робить `close`, producer завершується з `-1`.

Тести, які перевіряють «будить», не мають залежати від `sleep`. Якщо потік не прокинеться, `pthread_join` зависне назавжди, тож тест обмежимо через `timeout` у `make test`.

## Критерії готовності

- `make` і `make test` чисті, усі тести (старі й нові) зелені.
- `make SAN=thread test` без жодного звіту ThreadSanitizer.
- `make SAN=address test` без звітів ASan.
- Злиття в `main` через Pull Request з гілки `core/queue`.
