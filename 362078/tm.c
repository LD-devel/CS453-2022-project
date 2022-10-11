/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdlib.h>
#include <string.h>

// Internal headers
#include <tm.h>

#include "macros.h"

/**
 * @brief Single linked list of dynamically allocated shared memory segments.
 */
struct segment_node {
    struct segment_node* prev;
    struct segment_node* next;
};
typedef struct segment_node* segment_list;

/**
 * @brief Struct for transaction context
*/
typedef struct region
{
    // TODO: create a fine-grained lock to be able to lock a write set
    void* start;    // Start of the shared memory region
    size_t size;    // Size of the memory segment (in bytes)
    size_t align;   // Size of a word in the shared memory region (in bytes)
    segment_list segments;// Shared memory segments dynamically allocated via tm_alloc within a transaction
    // *segments* does not contain the first non-free-able segment
    // allocated with *tm_create*
} mem_region;


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) {
    // Instantiate a region to have context info for all 
    // subsequent transactions in the shared memory region
    mem_region* region = (mem_region*) malloc(sizeof(mem_region));

    // malloc returns a nullpointer in case of failure
    // the unlikely keyword lets the compiler optimize according 
    // to execution path probability
    if (unlikely(!region)) {
        return invalid_shared;
    }

    // Try to allocate the first non-fee-able segment of the 
    // shared memory region
    if (posix_memalign(&(region->start), align, size) != 0) {
        free(region);
        return invalid_shared;
    }


    // create an instance of a GVC
    //  Do we use a shared one for all memory regions or one GVC for each memory region?
    //  Maybe multiple GVCs allow for better concurrent performance.

    // 0 over the start memory segment
    // TODO: do we actually need to do this? 
    // possible performance drag
    memset(region->start, 0, size);

    // Set all remaining context in fo in region and return it's pointer
    region->segments    = NULL;
    region->size        = size;
    region->align       = align;
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t unused(shared)) {
    mem_region* region = (mem_region*) shared;

    // TODO: free anything that region points to
    // TODO free linked list region->segments

    free(region->start);

    // We want to free region last, to be able to free all
    // memory it points to
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) {
    // TODO: tm_start(shared_t)
    return NULL;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t unused(shared)) {
    // TODO: tm_size(shared_t)
    return 0;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t unused(shared)) {
    // TODO: tm_align(shared_t)
    return 0;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool unused(is_ro)) {
    // TODO: tm_begin(shared_t)

    // create local variable $rv$ (read-version)
    // sample GVC and store it in rv

    // if (!is_ro)
    //  set up stuff for a speculative execution
    //  store info whether transaction is_ro

    return invalid_tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t unused(shared), tx_t unused(tx)) {
    // TODO: tm_end(shared_t, tx_t)

    // if read-only
    //      lock the required memory segments from the read set
    //      perform all read operations
    //      unlock the required memory segments

    return false;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t unused(shared), tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)

    // if read-only 
    //      simply aggregate all read operations

    return false;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t unused(shared), tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    // TODO: tm_write(shared_t, tx_t, void const*, size_t, void*)
    return false;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t unused(shared), tx_t unused(tx), size_t unused(size), void** unused(target)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)

    return false;
}
