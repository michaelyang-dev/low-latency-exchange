# Market-data stage (07 §3, WP N-18): the egress ring shared by the release-gated
# egress stages, the MoldUDP64 publisher (lines A/B), the re-request store and the
# GLIMPSE-style snapshot service.
lle_library(lle_md HEADER_ONLY
  DEPS lle_concurrent lle_moldudp64 lle_glimpse lle_itch50 lle_outlog lle_soupbin lle_net_common lle_log)
