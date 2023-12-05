#include "hypsec.h"

/*
 * Dynamic Page Manager (DPM)
 */

// DPM handlers and code go in here
u64 __hyp_text alloc_region(u64 start_addr_region, u64 region_size_bytes)
{
  // Code here
  // Called by the host to hand a region to DPM

  return 0;
}

u64 __hyp_text reclaim_regions(u64 output_start_addr)
{
  // Code here
  // Called by the host when it wants regions back from DPM

  return 0;
}
