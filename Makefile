EXE := enumy

SRC_DIR := src
SCAN_DIR := src/scans
OBJ_DIR := obj
OBJ_SCAN_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

SRC_SCAN := $(wildcard $(SCAN_DIR)/*.c)
OBJ_SCAN := $(SRC_SCAN:$(SCAN_DIR)/%.c=$(OBJ_SCAN_DIR)/%.o)

CPPFLAGS := -Iinclude -lcap
LDFLAGS  := -Llib -lcap
LDLIBS := -lpthread -lm -lcap
CFLAGS := -W 

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) $(OBJ_SCAN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -lpthread $(STATIC) $(ARCH) -g -Wall -Wextra -O3 

$(EXE_SCAN): $(OBJ_SCAN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -lpthread $(STATIC) $(ARCH) -g -Wall -Wextra -O3 
	
$(OBJ_SCAN_DIR)/%.o: $(SCAN_DIR)/%.c | $(OBJ_SCAN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -lpthread $(STATIC) $(ARCH) -g -Wall -Wextra -O3 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -lpthread $(STATIC) $(ARCH) -g -Wall -Wextra -O3 

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ) $(OBJ_SCAN)

.PHONY: cov

cov: 
	make clean 
	cov-build --dir cov-int make 
	tar czvf enumy-cov.tgz cov-int
	curl --form token=`cat cov-token` \
	--form email=`cat email` \
	--form file=@enumy-cov.tgz\
	--form version="Version" \
	--form description="Description" \
	https://scan.coverity.com/builds?project=luke-goddard%2Fenumy

.PHONY: asci

ascii: 
	make clean 
	make 
	termtosvg docs/svg/example.svg -c "./enumy -t 8"
