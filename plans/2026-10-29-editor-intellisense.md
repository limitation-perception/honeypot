# Червоні підкреслення в редакторі (IntelliSense)

Дата: 2026-10-29

## Причина

У VS Code встановлене розширення Microsoft C/C++ (`ms-vscode.cpptools`), а не clangd.
Воно **не читає** `compile_flags.txt`, тому не знає, що потрібні `-Isrc`, `-Itests/unity` і `-D_POSIX_C_SOURCE=200809L`, і показує хибні помилки:
`'core/event.h' file not found`, `undeclared identifier` тощо.

Сам код правильний: gcc збирає його з `-Werror`, а `clangd --check` на тих самих прапорцях показує 0 помилок.

## Рішення

Обидва інструменти (cpptools і clangd) вміють читати стандартний `compile_commands.json`. Будемо генерувати його з Makefile, щоб прапорці жили в одному місці (SSOT), а не дублювалися в окремих файлах.

1. **Makefile:** ціль `compile_commands.json`. Для кожного `.c` з `src/` і `tests/` вона записує команду з тими самими `$(CFLAGS)`, що й справжня збірка (для тестів додатково `-Itests/unity`). Ціль `all` залежить від неї, тож файл оновлюється при кожному `make`.
2. **`.vscode/c_cpp_properties.json`:** одна конфігурація з `"compileCommands": "${workspaceFolder}/compile_commands.json"`.
3. **Видалити `compile_flags.txt`:** clangd теж читатиме `compile_commands.json`.
4. **`.gitignore`:** додати `compile_commands.json`, бо це згенерований файл. `.vscode/c_cpp_properties.json` комітимо, щоб у команди все працювало одразу.

## Після виконання

- Запустити `make`.
- У VS Code: `Ctrl+Shift+P` → `C/C++: Reset IntelliSense Database` (або просто перезапустити вікно).

## Перевірка

- Підкреслень у `src/` і `tests/` немає.
- `make`, `make test`, `make SAN=thread test` працюють як раніше.
