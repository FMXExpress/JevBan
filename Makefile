FPC      ?= fpc
FPCFLAGS ?= -O2 -Sh -ve -vm6058
BUILD    := build

.PHONY: all clean test

all: $(BUILD)/jevban

$(BUILD)/jevban: *.pas jevban.lpr
	@mkdir -p $(BUILD)/units
	$(FPC) $(FPCFLAGS) -FU$(BUILD)/units -o$(BUILD)/jevban jevban.lpr

$(BUILD)/jevban_test: *.pas tests/jevban_test.lpr
	@mkdir -p $(BUILD)/units
	$(FPC) $(FPCFLAGS) -Fu. -FU$(BUILD)/units -o$(BUILD)/jevban_test tests/jevban_test.lpr

test: $(BUILD)/jevban $(BUILD)/jevban_test
	cp tests/sample_access.log $(BUILD)/
	./$(BUILD)/jevban_test
	./$(BUILD)/jevban --test tests/sample_access.log --mode rules

clean:
	rm -rf $(BUILD)
