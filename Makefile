# contrib/pg_rest/Makefile

MODULES = pg_rest

EXTENSION = pg_rest
DATA = pg_rest--1.0.sql
# PGFILEDESC = "pg_rest - various functions that return tables"

REGRESS = pg_rest

LDFLAGS_SL += $(filter -lm, -levent $(LIBS))

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_rest
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

SHLIB_LINK += $(filter -levent  -L /usr/lib/x86_64-linux-gnu/  $(LIBS)) 