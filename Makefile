TOP = ..

include $(TOP)/mk/base.mk

ifeq ($(HOSTNAME),ender)
	SRCS_PL = signzone.pl
	SRCS_MAN1 = $(SRCS_PL)
endif

include $(TOP)/mk/Perl.mk
