CXX ?= c++

CPPFLAGS := -Ishared/include
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=

BUILD_DIR := build
BACKEND_SOURCE := backend/src/main.cpp
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

.PHONY: all backend worker run-backend run-worker check-drogon clean help

all: worker backend

backend: check-drogon $(BACKEND_TARGET)

worker: $(WORKER_TARGET)

$(BACKEND_TARGET): $(BACKEND_SOURCE) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DROGON_CFLAGS) $< -o $@ $(LDFLAGS) $(DROGON_LIBS)

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
	@echo "  make run-worker   Собрать и запустить worker"
	@echo "  make run-backend  Собрать и запустить API"
	@echo "  make clean        Удалить каталог build"
