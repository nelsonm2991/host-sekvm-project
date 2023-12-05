#include "hypsec.h"

/*
 * Dynamic Page Manager (DPM)
 */

// DPM handlers and code go in here
u64 __hyp_text alloc_region(u64 start_addr_region, u64 region_size_bytes)
{
  // Code here
  // Called by the host to hand a region to DPM

  // Code line
  // Check that el2_data->dpm_info has received it's first page
  // If dpm_info not initialized and the region_size_bytes is not one page
  //   return 1
  // if dpm_info not initialized and region_size_bytes is a page
  //   treat this as the initial page
  //   set the very top dpm_region struct info to be about this region
  //   update the el2_data->dpm_info with this information as well
  //   return successful
  //
  // At this point we know the DPM is initialized, so we can treat this as a normal
  // region receipt. If we can find space for the new region metadata, then
  // we will use it (add a helper function for searching this)
  //
  // If we can't find another available metadata struct -> return error
  // If we found another available metadata struct:
  // populate the region struct with the necessary info
  // Add it to the rear of the circular linkedlist we are maintaining
  // Return successful
  // Note: we likely need a lock on the linked list for concurrent issues,
  // so add one of those to the el2_data struct to serve as the overall system lock

  return 0;
}

u64 __hyp_text reclaim_regions(u64 output_start_addr)
{
  // Code here
  // Called by the host when it wants regions back from DPM

  return 0;
}
