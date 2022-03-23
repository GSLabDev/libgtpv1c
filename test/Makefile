# Copyright (c) 2022 Great Software Laboratory (GS Lab)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ROOT=.

TARGET_DIR := $(ROOT)/lib
BUILDDIR := $(ROOT)/obj
SRCDIR := $(ROOT)

CFLAGS += -I$(ROOT)/../include/
CFLAGS += -Wall
CFLAGS += --coverage

CC := gcc
OUTPUT := -o
LIBS := -L$(ROOT)/../lib/
LIBS += -lcunit
LIBS += -lgtpv1c
LIBS += -lgcov
SRCS := $(SRCDIR)/fill_gtpv1_ies.c
SRCS += $(SRCDIR)/test_decoder_gtpv1_ies.c
SRCS += $(SRCDIR)/test_encoder_gtpv1_ies.c
SRCS += $(SRCDIR)/test_encoder_gtpv1_messages.c
SRCS += $(SRCDIR)/test_decoder_gtpv1_messages.c
SRCS += $(SRCDIR)/main.c
TARGET := gtpv1c_test

OBJS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SRCS:.c=.o))

$(TARGET_DIR)/$(TARGET): $(OBJS)
	@mkdir -p $(TARGET_DIR)
	@mkdir -p $(BUILDDIR)
	
	$(CC) $(LDFLAGS) $(OUTPUT) $(TARGET_DIR)/$(TARGET) $^ $(LIBS)

$(BUILDDIR)/%.o: $(ROOT)/%.c
	@mkdir -p $(BUILDDIR)
	gcc $(CFLAGS) -c -o $@ $< 

all:$(TARGET)

clean:
	@echo " $(RM) -r $(BUILDDIR) $(TARGET_DIR)"; $(RM) -r $(BUILDDIR) $(TARGET_DIR)

.PHONY: clean

