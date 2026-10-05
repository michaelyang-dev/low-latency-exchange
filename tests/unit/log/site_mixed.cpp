// One translation unit with nlog sites in an inline function and in an ordinary
// function (NlogSites.InlineAndPlainSitesShareATranslationUnit). GCC rejected this
// ("section type conflict") while a non-inline site's slot had internal linkage and an
// inline one's was COMDAT; every slot is now keyed by its site (nlog.h, SiteSlot).
#include "site_helpers.h"

namespace lle::nlog::test {

void log_from_mixed_tu() {
  log_from_inline_function();  // the header-inline site, also used by site_inline_a/b
  NLOG_INFO("mixed-tu-plain-site {}", 2);
}

}  // namespace lle::nlog::test
