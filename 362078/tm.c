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
#include "gvc.h"
#include "macros.h"
#include "lock.h"
#include "shared-lock.h"

/**
 * @brief Single linked list of dynamically allocated shared memory segments.

struct segment_node {
    struct segment_node* prev;
    struct segment_node* next;
    // TODO: amend by pointer or pointer to memory word here
    unsigned int versioned_mem_lock;
};
typedef struct segment_node* segment_list; */

/**
 * @brief Struct for the context of all transactions in one shared memory region
*/
typedef struct region
{
    // We use one global version clock per shared memory region
    gvc regional_gvc;
    // TODO: create a fine-grained lock to be able to lock a write set
    void* start;    // Start of the shared memory region
    size_t size;    // Size of the first memory segment (in bytes)
    unsigned int versioned_mem_lock; // versioned memory lock of the first segment
    size_t align;   // Size of a word in the shared memory region (in bytes)

    // Management of memory segments
    struct lock_t segments_lock; 
    uint16_t ctr;
    void* segment_addresses[2^16];
    void* segment_locks[2^16];
    // TODO: add queue

    // TODO: we need some data-structure to store read write sets
    // of transactions

} mem_region;

/**
 * @brief Determine and reserve the next free index in the array of memory segments
 * @param region Pointer to the region
 * @return Next free index in the array of memory segments
*/
uint16_t get_seg_index(shared_t shared){
    // TODO: throw exception if ctr > 2^16
    mem_region* region = (mem_region *)shared;
    lock_acquire(&(region->segments_lock));
    uint16_t tmp_ctr = region->ctr++;
    lock_release(&(region->segments_lock));
    return tmp_ctr;
}

/**
 * @brief Hand back an index in the array of memory segments
 * due to either failure of a transaction or freeing of memory
 * @param shared Pointer to the region
 * @param index_old index to be freed
*/
void free_seg_index(shared_t unused(shared), uint16_t unused(index_old)){
    // TODO: this
}

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
    if (posix_memalign(&(region->segment_addresses[0]), align, size) != 0) {
        free(region);
        return invalid_shared;
    }

    // Init the global version clock for this shared memory region
    // and the lock for the list of segments
    if (!gvc_init(&(region->regional_gvc)) ||
        !lock_init(&(region->segments_lock))) {
        free(region->start);
        free(region);
    }

    // 0 over the start memory segment
    // TODO: do we actually need to do this? 
    // possible performance drag
    memset(region->segment_addresses[0], 0, size);

    // Set all remaining context in fo in region and return it's pointer
    // TODO: init queue for allocation index feeder
    //region->segments             = NULL;
    region->size                 = size;
    region->versioned_mem_lock   = 0;
    region->align                = align;
    region->ctr                  = 1; // The first index is reserved
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    mem_region* region = (mem_region*) shared;

    // TODO: free anything that region points to
    // TODO: free segments

    free(region->segment_addresses[0]); // free the non-free-able 
    gvc_clean_up(&(region->regional_gvc));
    lock_cleanup(&(region->segments_lock));
    // We want to free region last, to be able to free all
    // memory it points to
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) {
    return ((mem_region*) shared)->segment_addresses[0];
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    return ((mem_region*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    return ((mem_region*) shared)->align;
}

typedef struct transaction {
    bool is_ro;
} tx_con; 

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool unused(is_ro)) {

    // TODO: Do we have to register the transaction with the region
    // for some reason? I don't see yet why we would.

    // Allocate memory for new transaction context.
    tx_con* tx_new = (tx_con*) malloc(sizeof(tx_con));
    if( unlikely(!tx_new)){
        return invalid_tx;
    }

    // if (!is_ro)
    //  set up stuff for a speculative execution
    //  store info whether transaction is_ro

    return (tx_t) tx_new;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t unused(shared), tx_t tx) {
    // TODO: tm_end(shared_t, tx_t)

    // if read-only
    //      lock the required memory segments from the read set
    //      perform all read operations
    //      unlock the required memory segments
    // TODO: if we keep track on whether there is another transaction wanting to write on our read-only memory, we can skip the locks if there are none

    // commit all read/alloc/write/free operations
    // only free memory segments from this transaction,
    // if they should not remain in the shared memory region
    
    // free the transaction context from memory
    free((tx_con*)tx);

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
    // TODO: tm_read(shaared_t, tx_t, void const*, size_t, void*)

    // if read-only 
    //      simply aggregate all read operations

    // if not read-oly first check, if this is a segment allocated in  the current transaction

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
    
    // first check, if this is a segment allocated in  the current transaction
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
    // TODO: use the transaction handle tx and the shared memory handle shared_t to avoid concurrent memory allocation

    /*
    // Allocate segment
    // 1. get the alignment from the pointer to the region
    size_t align = ((mem_region*) shared)->align;
    align = align < sizeof(struct segment_node*) ? sizeof(void*) : align;

    // sn is a pointer to a segment_node
    // we cast that into a pointer to a memory word (void**)
    struct segment_node* sn;
    if (unlikely(posix_memalign((void**)&sn, align, sizeof(struct segment_node) + size) != 0)) return nomem_alloc; // Failed allocation!

    // Make this segment the last one in the linked list
    sn->prev = NULL;
    sn->next = ((mem_region*) shared)->segments;
    if (sn->next) sn->next->prev = sn;
    // Also let the linked list now that it has a new last element
    // TODO: WARNING: Why would this work if two threads concurrently allocate memory?
    // We get a concurrent write to the linked list
    // I don't think this should work
    ((mem_region*) shared)->segments = sn;

    // We cast sn into an uintptr_t because pointer arithmetic on void* pointers is illegal
    void* segment = (void*) ((uintptr_t) sn + sizeof(struct segment_node));
    // 0 everything
    memset(segment, 0, size);
    // now that everything is done, we can set the value of the target pointer
    *target = segment;
    return success_alloc;*/

    return nomem_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: use the transaction id tx and the shared memory handle shared_t to avoid concurrent memory allocation

    /*struct segment_node* sn = (struct segment_node*) ((uintptr_t) target - sizeof(struct segment_node));

    if (sn->prev) sn->prev->next = sn->next;
    else ((struct region*) shared)->segments*/

    return false;
}
