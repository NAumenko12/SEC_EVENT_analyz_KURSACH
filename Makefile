CXX ?= c++

CPPFLAGS := -Ishared/include -Ibackend/include
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
NPM ?= npm

BUILD_DIR := build
BACKEND_SOURCES := $(wildcard backend/src/*.cpp)
WORKER_SOURCE := worker/src/main.cpp
BACKEND_TARGET := $(BUILD_DIR)/security_analyzer_api
WORKER_TARGET := $(BUILD_DIR)/security_analyzer_worker

DROGON_PREFIX ?= $(shell brew --prefix drogon 2>/dev/null)
DROGON_CFLAGS := -I$(DROGON_PREFIX)/include \
	$(shell pkg-config --cflags jsoncpp openssl 2>/dev/null)
DROGON_LIBS := -L$(DROGON_PREFIX)/lib \
	-Wl,-rpath,$(DROGON_PREFIX)/lib \
	-ldrogon -ltrantor \
	$(shell pkg-config --libs jsoncpp openssl 2>/dev/null) \
	-lz -lsqlite3

LIBPQ_PREFIX ?= $(shell brew --prefix libpq 2>/dev/null)
LIBPQ_CFLAGS := -I$(LIBPQ_PREFIX)/include
LIBPQ_LIBS := -L$(LIBPQ_PREFIX)/lib \
	-Wl,-rpath,$(LIBPQ_PREFIX)/lib \
	-lpq

RUSTUP_PREFIX ?= $(shell brew --prefix rustup 2>/dev/null)

.PHONY: all backend worker frontend frontend-lint desktop run-backend run-worker \
	check-drogon check-libpq check-node check-rust clean help

all: worker backend

backend: check-drogon check-libpq $(BACKEND_TARGET)

worker: $(WORKER_TARGET)

frontend: check-node
	cd frontend && $(NPM) run build

frontend-lint: check-node
	cd frontend && $(NPM) run lint

desktop: check-node check-rust
	cd frontend && PATH="$(RUSTUP_PREFIX)/bin:$$PATH" \
		$(NPM) run tauri build -- --debug

$(BACKEND_TARGET): $(BACKEND_SOURCES) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DROGON_CFLAGS) $(LIBPQ_CFLAGS) $^ -o $@ $(LDFLAGS) $(DROGON_LIBS) $(LIBPQ_LIBS)

$(WORKER_TARGET): $(WORKER_SOURCE) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

check-drogon:
	@command -v brew >/dev/null 2>&1 || { \
		echo "Ошибка: Homebrew не установлен."; \
		exit 1; \
	}
	@command -v pkg-config >/dev/null 2>&1 || { \
		echo "Ошибка: pkg-config не установлен."; \
		exit 1; \
	}
	@test -f "$(DROGON_PREFIX)/include/drogon/drogon.h" || { \
		echo "Ошибка: заголовочные файлы Drogon не найдены."; \
		echo "Установите Drogon командой brew install drogon."; \
		exit 1; \
	}
	@test -f "$(DROGON_PREFIX)/lib/libdrogon.dylib" || { \
		echo "Ошибка: библиотека Drogon не найдена."; \
		exit 1; \
	}

check-libpq:
	@test -f "$(LIBPQ_PREFIX)/include/libpq-fe.h" || { \
		echo "Ошибка: заголовочные файлы libpq не найдены."; \
		echo "Установите libpq командой brew install libpq."; \
		exit 1; \
	}
	@test -f "$(LIBPQ_PREFIX)/lib/libpq.dylib" || { \
		echo "Ошибка: библиотека libpq не найдена."; \
		exit 1; \
	}

check-node:
	@command -v $(NPM) >/dev/null 2>&1 || { \
		echo "Ошибка: npm не найден. Установите Node.js."; \
		exit 1; \
	}
	@test -d frontend/node_modules || { \
		echo "Ошибка: зависимости frontend не установлены."; \
		echo "Выполните cd frontend && npm install."; \
		exit 1; \
	}

check-rust:
	@test -x "$(RUSTUP_PREFIX)/bin/cargo" || { \
		echo "Ошибка: Rust toolchain не найден."; \
		echo "Установите rustup и stable toolchain."; \
		exit 1; \
	}

run-backend: backend
	./$(BACKEND_TARGET)

run-worker: worker
	./$(WORKER_TARGET)

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Доступные команды:"
	@echo "  make worker       Собрать C++ worker"
	@echo "  make backend      Собрать Drogon API"
	@echo "  make all          Собрать worker и API"
	@echo "  make frontend     Собрать React-интерфейс"
	@echo "  make frontend-lint Проверить React линтером"
	@echo "  make desktop      Собрать macOS-приложение Tauri"
	@echo "  make run-worker   Собрать и запустить worker"
	@echo "  make run-backend  Собрать и запустить API"
	@echo "  make clean        Удалить каталог build"
