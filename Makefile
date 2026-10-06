CXX ?= c++
CPPFLAGS := -Ishared/include -Ibackend/include -Iworker/include
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
NPM ?= npm
BUILD_DIR := build
BACKEND_SOURCES := $(wildcard backend/src/*.cpp)
WORKER_SOURCES := $(wildcard worker/src/*.cpp) backend/src/Database.cpp
BACKEND_TARGET := $(BUILD_DIR)/security_analyzer_api
WORKER_TARGET := $(BUILD_DIR)/security_analyzer_worker
PARSER_TEST_TARGET := $(BUILD_DIR)/auth_log_parser_test
DETECTION_TEST_TARGET := $(BUILD_DIR)/detection_engine_test

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

KAFKA_PREFIX ?= $(shell brew --prefix librdkafka 2>/dev/null)
KAFKA_CFLAGS := -I$(KAFKA_PREFIX)/include
KAFKA_LIBS := -L$(KAFKA_PREFIX)/lib \
	-Wl,-rpath,$(KAFKA_PREFIX)/lib \
	-lrdkafka++ -lrdkafka
JSONCPP_CFLAGS := $(shell pkg-config --cflags jsoncpp 2>/dev/null)
JSONCPP_LIBS := $(shell pkg-config --libs jsoncpp 2>/dev/null)

SODIUM_PREFIX ?= $(shell brew --prefix libsodium 2>/dev/null)
SODIUM_CFLAGS := -I$(SODIUM_PREFIX)/include
SODIUM_LIBS := -L$(SODIUM_PREFIX)/lib \
	-Wl,-rpath,$(SODIUM_PREFIX)/lib \
	-lsodium

RUSTUP_PREFIX ?= $(shell brew --prefix rustup 2>/dev/null)

.PHONY: all backend worker test-worker frontend frontend-lint desktop run-backend run-worker \
	check-drogon check-libpq check-librdkafka check-libsodium check-node \
	check-rust clean help

all: worker backend

backend: check-drogon check-libpq check-librdkafka check-libsodium $(BACKEND_TARGET)

worker: check-libpq check-librdkafka $(WORKER_TARGET)

test-worker: $(PARSER_TEST_TARGET) $(DETECTION_TEST_TARGET)
	./$(PARSER_TEST_TARGET)
	./$(DETECTION_TEST_TARGET)

frontend: check-node
	cd frontend && $(NPM) run build

frontend-lint: check-node
	cd frontend && $(NPM) run lint

desktop: check-node check-rust
	cd frontend && PATH="$(RUSTUP_PREFIX)/bin:$$PATH" \
		$(NPM) run tauri build -- --debug

$(BACKEND_TARGET): $(BACKEND_SOURCES) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DROGON_CFLAGS) $(LIBPQ_CFLAGS) $(KAFKA_CFLAGS) $(SODIUM_CFLAGS) $^ -o $@ $(LDFLAGS) $(DROGON_LIBS) $(LIBPQ_LIBS) $(KAFKA_LIBS) $(SODIUM_LIBS)

$(WORKER_TARGET): $(WORKER_SOURCES) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIBPQ_CFLAGS) $(KAFKA_CFLAGS) $(JSONCPP_CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBPQ_LIBS) $(KAFKA_LIBS) $(JSONCPP_LIBS)

$(PARSER_TEST_TARGET): worker/tests/AuthLogParserTest.cpp \
	worker/src/AuthLogParser.cpp worker/src/ParserFactory.cpp \
	worker/src/TextLogReader.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@

$(DETECTION_TEST_TARGET): worker/tests/DetectionEngineTest.cpp \
	worker/src/DetectionEngine.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@

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

check-librdkafka:
	@test -f "$(KAFKA_PREFIX)/include/librdkafka/rdkafkacpp.h" || { \
		echo "Ошибка: заголовочные файлы librdkafka не найдены."; \
		echo "Установите librdkafka командой brew install librdkafka."; \
		exit 1; \
	}
	@test -f "$(KAFKA_PREFIX)/lib/librdkafka++.dylib" || { \
		echo "Ошибка: библиотека librdkafka++ не найдена."; \
		exit 1; \
	}

check-libsodium:
	@test -f "$(SODIUM_PREFIX)/include/sodium.h" || { \
		echo "Ошибка: заголовочные файлы libsodium не найдены."; \
		echo "Установите libsodium командой brew install libsodium."; \
		exit 1; \
	}
	@test -f "$(SODIUM_PREFIX)/lib/libsodium.dylib" || { \
		echo "Ошибка: библиотека libsodium не найдена."; \
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
	@echo "  make test-worker  Проверить парсер Linux auth.log"
	@echo "  make backend      Собрать Drogon API"
	@echo "  make all          Собрать worker и API"
	@echo "  make frontend     Собрать React-интерфейс"
	@echo "  make frontend-lint Проверить React линтером"
	@echo "  make desktop      Собрать macOS-приложение Tauri"
	@echo "  make run-worker   Собрать и запустить worker"
	@echo "  make run-backend  Собрать и запустить API"
	@echo "  make clean        Удалить каталог build"
