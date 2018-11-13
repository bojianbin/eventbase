# Run target in all subdirectories in SUBDIRS
%/all:
	@echo "ENTER $(@D) (ALL $(PF_TARGET))"
	$(Q)$(MAKE) -C $(@D) all
	@echo "LEAVE $(@D)"

%/clean:
	@echo "ENTER $(@D) (CLEAN $(PF_TARGET))"
	$(Q)$(MAKE) -C $(@D) clean
	@echo "LEAVE $(@D)"



all: $(PKG_SUBDIRS:%=%/all) extra_all

clean: $(PKG_SUBDIRS:%=%/clean) extra_clean



.PHONY: clean all clean_build_dir