# Client-side programs' cores (07 §3): mold_replay's publisher, refclient's feed
# handler / strategy / HA order entry, checkpoints and reports.
lle_test(client_test
  SOURCES replay_feed_test.cpp feed_handler_test.cpp strategy_test.cpp order_entry_test.cpp checkpoints_test.cpp
  DEPS lle_client)
# The lab instruments' cores (M13): variants, TX-stamp attribution, PHC map, ttt plan and
# verdict, calibration, record files, loadgen v2 profile/schedule/risk, backlog check.
lle_test(client_instruments_test SOURCES instruments_test.cpp DEPS lle_client lle_metrics)
# Allocation counting replaces the global operator new: its own binary.
lle_test(client_alloc_test SOURCES hot_path_alloc_test.cpp DEPS lle_client)
# Against the real sequencer and engine in-process: loadgen's accounting, itch2ouch.
lle_test(client_exchange_test SOURCES loadgen_test.cpp itch2ouch_test.cpp DEPS lle_client_exchange)
