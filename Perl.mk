INST_PL = $(SRCS_PL:%.pl=$(INST_BIN)/%)
INST_POD1 = $(SRCS_MAN1:%.pl=$(INST_MAN1)/%.1.bz2)

$(INST_BIN):
	mkdir -p $@

$(INST_BIN)/%:%.pl
	$(PERL) -c $<
	echo "#!$(PERL)" > $@
	chmod 755 $@
	cat $< >> $@

$(INST_MAN1):
	mkdir -p $@

$(INST_MAN1)/%.1.bz2:%.pl
	pod2man $< | bzip2 --best > $@

dummy:
	@echo use make install

install: $(INST_BIN) $(INST_PL) $(INST_MAN1) $(INST_POD1)
