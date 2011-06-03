TOP = ..

include $(TOP)/mk/base.mk

ifeq ($(HOSTNAME),ender)
	SRCS_PL = signzone.pl
endif

include $(TOP)/mk/Perl.mk
