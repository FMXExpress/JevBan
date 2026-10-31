FPC      ?= fpc
FPCFLAGS ?= -O2 -Sh -ve -vm6058
BUILD    := build

.PHONY: all clean test llama

all: $(BUILD)/jevban

$(BUILD)/jevban: *.pas jevban.lpr data/badpaths.txt
	@mkdir -p $(BUILD)/units
	$(FPC) $(FPCFLAGS) -FU$(BUILD)/units -o$(BUILD)/jevban jevban.lpr
	cp data/badpaths.txt $(BUILD)/

$(BUILD)/jevban_test: *.pas tests/jevban_test.lpr
	@mkdir -p $(BUILD)/units
	$(FPC) $(FPCFLAGS) -Fu. -FU$(BUILD)/units -o$(BUILD)/jevban_test tests/jevban_test.lpr

test: $(BUILD)/jevban $(BUILD)/jevban_test
	cp tests/sample_access.log data/badpaths.txt $(BUILD)/
	./$(BUILD)/jevban_test
	./$(BUILD)/jevban --test tests/sample_access.log --mode rules

# llama.cpp shared libraries next to the binary (mode = local); the tag Ban.Llama.pas binds
LLAMA_TAG := b11985
llama:
	[ -d llama.cpp ] || git clone --depth 1 --branch $(LLAMA_TAG) https://github.com/ggml-org/llama.cpp llama.cpp
	cmake -S llama.cpp -B llama.cpp/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
	  -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF \
	  -DLLAMA_BUILD_TOOLS=OFF -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON '-DCMAKE_INSTALL_RPATH=$$ORIGIN' \
	  -DGGML_OPENMP=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON $(LLAMA_CMAKE)
	cmake --build llama.cpp/build -j --target llama \
	  $$(cmake --build llama.cpp/build --target help | grep -oE 'ggml-cpu-[a-z0-9]+' | grep -v feats | sort -u)
	@mkdir -p $(BUILD)
	cp -a llama.cpp/build/bin/lib*.so* $(BUILD)/

clean:
	rm -rf $(BUILD)
