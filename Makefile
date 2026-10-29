CC      := gcc
CFLAGS  := -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror -g -Isrc -MMD -MP
LDFLAGS :=
LDLIBS  := -lpthread

ifeq ($(SAN),1)
BUILD   := build/san
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
else
BUILD   := build
endif

BIN       := $(BUILD)/honeytrap
SRCS      := $(shell find src -name '*.c')
OBJS      := $(SRCS:%.c=$(BUILD)/%.o)
LIB_OBJS  := $(filter-out $(BUILD)/src/main.o,$(OBJS))

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/%.c=$(BUILD)/tests/%)
UNITY_OBJ := $(BUILD)/tests/unity/unity.o

.PHONY: all test clean
.SECONDARY:

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(UNITY_OBJ): tests/unity/unity.c
	@mkdir -p $(dir $@)
	$(CC) -std=c11 -g $(filter -fsanitize=%,$(CFLAGS)) -c -o $@ $<

$(BUILD)/tests/test_%: $(BUILD)/tests/test_%.o $(LIB_OBJS) $(UNITY_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/%.o: CFLAGS += -Itests/unity

test: $(TEST_BINS)
	@fail=0; for t in $^; do echo "== $$t"; ./$$t || fail=1; done; exit $$fail

clean:
	rm -rf build

-include $(OBJS:.o=.d) $(TEST_BINS:=.d)
