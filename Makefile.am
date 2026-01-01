SUBDIRS = src

EXTRA_DIST = \
    autogen.sh \
    VERSION \
    etc/Mcaster1BackDraft.yaml.example \
    etc/backdraft-waf.yaml.example \
    etc/backdraft-logd.yaml.example \
    etc/Mcaster1BackDraft.service \
    etc/mcaster1-backdraft-waf.service \
    etc/mcaster1-backdraft-logd.service \
    sql/schema.sql \
    scripts/setup.sh \
    scripts/systemd-setup.sh

install-data-local:
	$(MKDIR_P) $(DESTDIR)/etc/Mcaster1BackDraft
	$(MKDIR_P) $(DESTDIR)/var/log/Mcaster1BackDraft
	if [ ! -f $(DESTDIR)/etc/Mcaster1BackDraft/Mcaster1BackDraft.yaml ]; then \
		$(INSTALL_DATA) etc/Mcaster1BackDraft.yaml.example \
		    $(DESTDIR)/etc/Mcaster1BackDraft/Mcaster1BackDraft.yaml; \
	fi
