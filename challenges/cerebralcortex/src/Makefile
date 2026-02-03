CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE = arm-none-eabi-size

TARGET := cerebralcortex

CFLAGS := -mcpu=cortex-m3 -mthumb -Os -g3 -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror \
  -fno-builtin -fno-common

LDFLAGS := -T linker.ld -Wl,--gc-sections -Wl,-Map=$(TARGET).map \
  -nostartfiles -specs=rdimon.specs

SRCS := startup.c fs.c cerebralcortex.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET).elf $(TARGET).bin
	$(SIZE) $(TARGET).elf

$(TARGET).elf: $(OBJS) linker.ld
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).bin $(TARGET).map

