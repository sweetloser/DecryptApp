
#clang++编译器
CLANG_BIN=`xcrun --sdk iphoneos --find clang++`

#架构
CLANG_UNIVERSAL=$(CLANG_BASE) -arch armv7 -arch armv7s -arch arm64


#sdk路径
SDK=`xcrun --sdk iphoneos --show-sdk-path`

#编译参数
CFLAGS = 

PLIST_TOOL=/usr/libexec/PlistBuddy

CLANG_BASE = $(CLANG_BIN) -Os $(CFLAGS) -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks
#$@--目标文件，$^--所有的依赖文件，$<--第一个依赖文件。
all: DecryptApp.dylib DecryptApp.plist
DecryptApp.dylib: DecryptApp.o
	$(CLANG_UNIVERSAL) -dynamiclib -framework Foundation -o $@ $^

%.o: ../DecryptApp/%.mm ../DecryptApp/CaptainHook.h
	$(CLANG_UNIVERSAL) -x objective-c++ -c -o $@ $<

DecryptApp.plist:
	rm -f $@
	touch $@
	echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict></dict></plist>' >> $@
	$(PLIST_TOOL) -c 'Add :Filter dict' $@
	$(PLIST_TOOL) -c 'Add :Filter:Bundles array' $@
	$(PLIST_TOOL) -c 'Add :Filter:Bundles: string com.SpringBoard' $@

clean:
	rm -f *.o DecryptApp.dylib *.plist







