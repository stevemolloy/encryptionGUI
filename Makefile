CC = clang
CFLAGS = -Wall -Wpedantic -Wextra -Werror -ggdb -std=c18
CINCLUDES = -I./includes/raylib/src
CLIBS = -L./includes/raylib/src -lm -lraylib -lgcrypt

SRC = src
OBJ = obj

SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

BINDIR = bin
BIN = $(BINDIR)/memo

all: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CINCLUDES) $^ -o $@ $(CLIBS)

$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CINCLUDES) -c $< -o $@

clean:
	rm -rf $(BINDIR) $(OBJ)

run: $(BIN)
	./$(BIN)

$(OBJ):
	@mkdir -p $@

