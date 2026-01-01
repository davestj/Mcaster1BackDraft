bin_PROGRAMS = Mcaster1BackDraft

Mcaster1BackDraft_SOURCES = \
    main.cpp \
    config.cpp \
    logger.cpp \
    dbpool.cpp \
    http_server.cpp \
    router.cpp \
    auth.cpp \
    api_handler.cpp \
    rule_engine.cpp \
    threat_scorer.cpp \
    nginx_manager.cpp \
    site_discovery.cpp \
    perf_monitor.cpp \
    waf_handler.cpp \
    threadpool.cpp \
    captcha_generator.cpp \
    botproof.cpp \
    smtp_client.cpp

Mcaster1BackDraft_CXXFLAGS = \
    $(OPENSSL_CFLAGS) \
    $(YAMLCPP_CFLAGS) \
    $(MYSQLCLIENT_CFLAGS) \
    $(GDLIB_CFLAGS) \
    -Wall -Wextra -O2

Mcaster1BackDraft_LDADD = \
    $(OPENSSL_LIBS) \
    $(YAMLCPP_LIBS) \
    $(MYSQLCLIENT_LIBS) \
    $(PTHREAD_LIBS) \
    $(GDLIB_LIBS)
