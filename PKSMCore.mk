mkfile_path	:=	$(abspath $(lastword $(MAKEFILE_LIST)))
current_dir	:=	$(SVEDIT_PATH)/$(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

SOURCES		:=	$(SOURCES) \
				$(current_dir)/source \
				$(current_dir)/source/i18n \
				$(current_dir)/source/personal \
				$(current_dir)/source/pkx \
				$(current_dir)/source/sav \
				$(current_dir)/source/utils \
				$(current_dir)/source/wcx \
				$(current_dir)/memecrypto

INCLUDES	:=	$(INCLUDES) \
				$(current_dir)/include \
				$(current_dir)/include/enums \
				$(current_dir)/include/personal \
				$(current_dir)/include/pkx \
				$(current_dir)/include/sav \
				$(current_dir)/include/utils \
				$(current_dir)/include/wcx \
				$(current_dir)/memecrypto


# format:
# 	clang-format -i -style=file $(foreach dir,$(SOURCES),$(wildcard $(dir)/*.c) $(wildcard $(dir)/*.cpp) $(wildcard $(dir)/*.hpp) $(wildcard $(dir)/*.h)) $(foreach dir,$(INCLUDES),$(wildcard $(dir)/*.h) $(wildcard $(dir)/*.hpp))
