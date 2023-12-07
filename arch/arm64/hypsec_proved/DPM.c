#include "hypsec.h"

/*
 * Dynamic Page Manager (DPM)
 */
 #define DPM_FLAG 0x80
 #define ALLOC_FLAG 0x1

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
  u64 res;
  struct el2_data *el2_data;

  // Verify DPM is initialized with it's first page for metadata
  acquire_lock_core();
  el2_data = get_el2_data_start();
  if (el2_data->dpm_info.base_page_addr == 0 && region_size_bytes / PAGE_SIZE != 1) {
    release_lock_core();
    return 1;
  }

  // Setup the very first DPM metadata page
  if (el2_data->dpm_info.base_page_addr == 0) {
    res = init_dpm(start_addr_region);
  }

  // Treat the region as a normal region
  else {
    res = setup_new_region();
  }


  release_lock_core();
  return res;
}

u64 __hyp_text reclaim_regions(u64 output_start_addr)
{
  // Code here
  // Called by the host when it wants regions back from DPM

  return 0;
}

u64 __hyp_text init_dpm(u64 start_addr)
{
  // Initialize DPM using this first page, only call with region size of 1 page
  //
  // Verify el2_data->dpm.base_page_addr is 0
  struct el2_data *el2_data;
  struct dpm_region region;

  el2_data = get_el2_data_start();
  if (el2_data->dpm.base_page_addr != 0) {
    print_string("\rinit_dpm called on already initialized DPM\n");
    return 1;
  }

  // start_addr is beginning of very first dpm_region struct
  // TODO: change this to just call setup_new_region after the check
  region = (struct dpm_region*) __el2_va(start_addr);
  region->start_addr = start_addr;
  region->page_count = 1;
  region->flags = 0 | DPM_FLAG | ALLOC_FLAG;
  region->prev = region;
  region->next = region;

  el2_data->dpm.base_page_addr = start_addr;
  el2_data->dpm.region_count = 1;
  el2_data->dpm.page_count = 1;

  return 0;
}

u64 __hyp_text setup_new_region(u64 start_addr, u64 size_bytes)
{
  // Add the new region into the pool of valid regions.
  // Make sure you have an available dpm_region struct in the metadata pages
  // If you need another metadata page, then search for one and perform
  // the necessary work. if you can't find one, return 1, and the
  // hypercall retry mechanism will make a call with a region
  // of size 1 which will then go through here and be used for metadata.
  //
  struct el2_data *el2_data;
  struct dpm_region region;
  struct dpm_region list_head;

  el2_data = get_el2_data_start();
  list_head = (struct dpm_region*) __el2_va(el2_data->dpm.base_page_addr);

  // Search the list to see if start_addr is already contained there
  // if it is --> error, otherwise proceed

  // Search the list again, but only consider regions with the DPM_FLAG set
  // for each possible dpm_region owned by DPM metadata:
  //   linear search for a vacant dpm_region
  //   if none found -> return NULL
  //   if found -> return u64 phys addr of the region
  //
  //   once a search call comes back non-NULL, break out of the search
  //   if you re-encounter the list_head, then return error since it means
  //   dpm has ran out of metadata pages and needs another 1


  return 0;
}
