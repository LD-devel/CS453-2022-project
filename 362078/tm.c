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

// Change to print debugging info
#define DEBUG 1

// External headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

// Internal headers
#include <tm.h>
#include "gvc.h"
#include "macros.h"
#include "lock.h"
#include "shared-lock.h"

/**
 * @brief Single linked list of writes
 */
struct write_node {
    struct write_node* prev;
    struct write_node* next;
    void* source;
    size_t size;
    void* target;
    bool locked;
};
typedef struct write_node* write_list;

/**
 * @brief Single linked list of reads
 */
struct read_node {
    struct read_node* prev;
    struct read_node* next;
    uint16_t segment_idx;
};
typedef struct read_node* read_list;

typedef struct transaction_context {
    bool is_ro;
    unsigned int rv;
    read_list reads;
    write_list writes;
} tx_con;

// Reads simply get inserted at the start of the list
void insert_read(read_list* reads_ptr, uint16_t segment_idx){
    struct read_node* n_read = (struct read_node*) malloc(sizeof(struct read_node));
    n_read->next = *reads_ptr;
    n_read->prev = NULL;
    n_read->segment_idx = segment_idx;
    *reads_ptr = n_read;
}

// Write get inserted in a sorted manner and intervals get updated accordingly
void insert_write(write_list* writes_ptr, void const* source,size_t size, void* target){
    struct write_node* n_write = (struct write_node*) malloc(sizeof(struct write_node));
    n_write->source = (void *)source;
    n_write->size = size;
    n_write->target = target;
    n_write->locked = false;

    if(!(*writes_ptr)){
        (*writes_ptr) = n_write;
        return;
    }

    // find the correct slot to insert
    // we ensure that prev<new and next>=new
    struct write_node* prev = NULL;
    struct write_node* next = *writes_ptr;
    while (next && next->target < target){
        prev = next;
        next = next->next;
    }
    if(prev) prev->next = n_write;
    n_write->prev = prev;
    n_write->next = next;
    if(next) next->prev = n_write;

    // update bounds of prev
    if(prev){
        unsigned char* prev_end = (unsigned char *)prev->target + (prev->size -1);
        unsigned char* new_start = (unsigned char *)n_write->target;
        if(prev_end >= new_start){
            prev->size = prev->size - (prev_end - new_start +1);
        }
    }
    // remove next if necessary
    unsigned char* new_end = (unsigned char *)n_write->target + (n_write->size -1);
    while(next && ((unsigned char *)next->target + (next->size -1)) <= new_end){
        n_write->next = next->next;
        free(next);
        next = n_write->next;
    }
    // update next's target address and size if necessary
    if(next){
        unsigned char * next_start = (unsigned char *)next->target;
        if(next_start <= new_end){
            size_t delta = (new_end - next_start) + 1;
            next->target = (void*)(new_end + 1);
            next->size = next->size - delta;
            next->source = (void*)((unsigned char *)next->source + delta);
        }
    }
}

/**
 * @brief Struct for the context of all transactions in one shared memory region
*/
typedef struct region
{
    // We use one global version clock per shared memory region
    //gvc regional_gvc;
    atomic_uint gvc;
    // TODO: create a fine-grained lock to be able to lock a write set
    void* start;    // Start of the shared memory region
    size_t size;    // Size of the first memory segment (in bytes)
    unsigned int versioned_mem_lock; // versioned memory lock of the first segment
    size_t align;   // Size of a word in the shared memory region (in bytes)

    // Management of memory segments
    struct lock_t segments_lock; 
    uint16_t ctr;
    void* segment_addresses[2^16];
    atomic_uint segment_locks[2^16];
    // TODO: add queue and index freeing mechanism
} mem_region;

/**
 * @brief Determine and reserve the next free index in the array of memory segments
 * @param region Pointer to the region
 * @return Next free index in the array of memory segments
*/
uint16_t get_seg_index(shared_t shared){
    mem_region* region = (mem_region *)shared;
    lock_acquire(&(region->segments_lock));
    uint16_t tmp_ctr = region->ctr++;
    // TODO: double check, if this is the correct fence
    atomic_thread_fence(memory_order_acquire);
    lock_release(&(region->segments_lock));
    return tmp_ctr;
}

// tries to lock write node's segment, if locked
// returns whether successful
bool lock_node(mem_region* region, struct write_node* node){
    if(!node->locked){
        uint16_t segment_idx = (uint16_t)((uint64_t)node->target >> 48);
        uint v_lock_val = atomic_load(&(region->segment_locks[segment_idx]));
        if (!(v_lock_val & 1)){
            node->locked = atomic_compare_exchange_weak(&(region->segment_locks[segment_idx]), &v_lock_val, v_lock_val +1);
        }
    }
    return node->locked;
}

// unlocks locked nodes corresponding segment lock
void unlock_all(mem_region* region, tx_con* transaction){
    struct write_node* curr = transaction->writes;
    bool first = true;
    uint16_t segment_idx = 0;
    while (curr){
        uint16_t segment_idx_curr = (uint16_t)((uint64_t)curr->target >> 48);
        if (first || segment_idx != segment_idx_curr){
            segment_idx = segment_idx_curr;
            //unlock_node(region, curr);
            if(curr->locked){
                uint16_t segment_idx = (uint16_t)((uint64_t)curr->target >> 48);
                uint v_lock_val = atomic_load(&(region->segment_locks[segment_idx]));
                atomic_store(&(region->segment_locks[segment_idx]), v_lock_val - 1);
                curr->locked = false;
            }
        }
        curr = curr->next;
        first = false;
    }
}

/**
 * Memcpy but bite-wise atomic.
 * This allows for undefined content when called concurrently,
 * but no undefined behaviour.
*/
void byte_wise_atomic_memcpy(void const* dest, void const* source, size_t count, memory_order order){
    for (size_t i = 0; i < count; ++i) {
        ((char*)(dest))[i] =
            atomic_load_explicit(((char*)(source))+i, order);
    }
    atomic_thread_fence(order);
}

/**
* Clean up after transaction
*/
void tx_clear(shared_t unused(shared), tx_t tx, bool unused(fail)){

    tx_con* transaction = (tx_con*)tx;
    // TODO: Free all memory segments that have not been commited yet
    // and hand back their index
    /*if (transaction->is_ro && !fail) printf("Read only success. \n");
    else if (transaction->is_ro && fail) {
        printf("Read only fail. \n");
    }
    else if (!transaction->is_ro && !fail) printf("Write success. \n");
    else 
    if (!transaction->is_ro && fail) {
        printf("Write fail. \n");
    }*/

    if (!transaction->is_ro){
        // Free the read and write set
        if (transaction->reads){
            struct read_node* curr = transaction->reads;
            while (curr->next){
                struct read_node* old = curr;
                curr = curr->next;
                free(old);
            }
            free(curr);
        }        
        if (transaction->writes){
            struct write_node* curr = transaction->writes;
            while (curr->next){
                struct write_node* old = curr;
                curr = curr->next;
                //printf("%p , %p \n", (void *)tx, old);
                free(old);
            }
            free(curr);
        }
    }
    free(transaction);
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
    if (posix_memalign(&(region->segment_addresses[1]), align, size) != 0) {
        free(region);
        return invalid_shared;
    }
    atomic_store(&(region->segment_locks[1]), 0);

    // Init the global version clock for this shared memory region
    // and the lock for the list of segments
    atomic_store(&(region->gvc),0);
    if (!lock_init(&(region->segments_lock))) {
        free(region->start);
        free(region);
        return invalid_shared;
    }

    // 0 over the start memory segment
    // TODO: do we actually need to do this? 
    // possible performance drag
    memset(region->segment_addresses[1], 0, size);

    // Set all remaining context in fo in region and return it's pointer
    // TODO: init queue for allocation index feeder
    //region->segments             = NULL;
    region->size                 = size;
    region->versioned_mem_lock   = 0;
    region->align                = align;
    region->ctr                  = 2; // The first index is reserved
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    mem_region* region = (mem_region*) shared;

    // TODO: free anything that region points to

    // free segments
    for (size_t i = 0; i < region->ctr; i++){
        // TODO: skip segments that have been freed already
        free(region->segment_addresses[i]);
    }
    
    free(region->segment_addresses[0]); // free the non-free-able 
    //gvc_clean_up(&(region->regional_gvc));
    lock_cleanup(&(region->segments_lock));
    free(region); // free region last
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) {
    void* pointer = (void *)(((uint64_t) 1u) << 48);
    #if DEBUG
    printf("start: %p \n", pointer);
    #endif
    return pointer;
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

/**
 * @brief Resolve a regional virtual address to a plain virtual 
 * address
 * @param shared Pointer to region providing the memory context
 * @param ptr Regional virtual address
 * @return A valid virtual address
*/
void* resolve_addr(shared_t shared, void const* ptr) {
    //offset: 0x0FFF && ptr;
    //index: 48 >> ptr
    void* real_base = ((mem_region *) shared)->segment_addresses[((uint64_t) ptr >> 48)];
    uint64_t vv_base = (((uint64_t) ptr) >> 48) << 48;
    uint64_t delta = ((uint64_t) ptr) - vv_base;
    return (void*)(((uint64_t) real_base) + delta);
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) {

    // TODO: Do we have to register the transaction with the region
    // for some reason? I don't see yet why we would.

    // Allocate memory for new transaction context.
    tx_con* tx_new = (tx_con*) malloc(sizeof(tx_con));
    if( unlikely(!tx_new)){
        return invalid_tx;
    }
    mem_region* region = (mem_region *)shared;
    tx_new->rv = atomic_load(&(region->gvc)); // sample GVC
    tx_new->is_ro = is_ro;                    // store is_ro
    tx_new->reads = NULL;
    tx_new->writes = NULL;
    return (tx_t) tx_new;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {

    tx_con* transaction = (tx_con *)tx;
    if (transaction->is_ro){
        tx_clear(shared, tx, false);
        #if DEBUG
        printf("Read succeeded. \n");
        #endif
        return true;
    }
    mem_region* region = (mem_region *)shared;

    // TL2 step 3: lock the write set with bounded spinning
    bool locked = true;
    for (size_t i = 0; i < 300; i++){
        locked = true;
        struct write_node* curr = transaction->writes;
        bool first = true;
        uint16_t segment_idx = 0;
        while (curr){
            uint16_t segment_idx_curr = (uint16_t)((uint64_t)curr->target >> 48);
            if (first || segment_idx != segment_idx_curr){
                segment_idx = segment_idx_curr;
                locked = locked && lock_node(region, curr);
            }
            curr = curr->next;
            first = false;
        }
        if (locked) break;
    }
    // If not all locks could be acquired, unlock the locked locks
    if(!locked){
        unlock_all(region, transaction);
        tx_clear(shared, tx, true);
        #if DEBUG
        printf("Write failed locking. \n");
        #endif
        return false;
    }

    // TL2 step 4: increment GVC
    uint wv = atomic_fetch_add(&(region->gvc),1) + 1;
    /*if (!gvc_increment(&(region->regional_gvc), &wv)){
        tx_clear(shared, tx, true);
        return false;
    }*/
    
    // TL2 step 5: validate the read set
    if(transaction->rv + 1 != wv){
        struct read_node* curr = transaction->reads;
        while (curr){
            uint16_t segment_idx = curr->segment_idx;
            uint v_lock_val = atomic_load(&(region->segment_locks[segment_idx]));
            bool valid = true;
            if ((v_lock_val >> 1) > transaction->rv) valid = false;
            // if segment is locked, check whether it is our own lock
            else if(v_lock_val & 1) {
                valid = false;
                struct write_node* curr_w   = transaction->writes;
                bool first_w                = true;
                uint16_t segment_idx_w      = 0;
                while (curr_w){
                    uint16_t segment_idx_curr_w = (uint16_t)((uint64_t)curr_w->target >> 48);
                    if (first_w || segment_idx_w != segment_idx_curr_w){
                        segment_idx_w = segment_idx_curr_w;
                        if (segment_idx_w == segment_idx){
                            valid = true;
                            break;
                        }
                    }
                    curr_w = curr_w->next;
                    first_w = false;
                }
            }
            if (!valid){
                // post-validation failed
                unlock_all(region, transaction);
                tx_clear(shared, tx, true);
                #if DEBUG
                printf("Post validation failed. \n");
                #endif
                return false;
            }
            curr = curr->next;
        }
    }

    // TL2 step 6: commit and release all locks
    struct write_node* curr = transaction->writes;
    bool first = true;
    uint16_t segment_idx = 0;
    while (curr){
        // write
        byte_wise_atomic_memcpy(resolve_addr(shared,curr->target), curr->source, curr->size, memory_order_acquire);
        // if this write is the last of the segment, unlock
        uint16_t segment_idx_curr = (uint16_t)((uint64_t)curr->target >> 48);
        if (!first && segment_idx != segment_idx_curr){
            // unlock last
            atomic_store(&(region->segment_locks[segment_idx]), wv<<1);
        }
        if (!curr->next){
            // unlock current
            atomic_store(&(region->segment_locks[segment_idx_curr]), wv<<1);
        }
        segment_idx = segment_idx_curr;
        curr = curr->next;
        first = false;
    }

    // TODO: allocate and free segments correctly
    #if DEBUG
    printf("Write succeeded. \n");
    #endif
    tx_clear(shared, tx, false);
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)
    mem_region* region = (mem_region *)shared;
    tx_con* transaction = (tx_con *)tx;
    uint16_t segment_idx = (uint16_t)((uint64_t) source >> 48);
    uint v_lock_val;
    //printf("read: %p , resolved: %p \n", source, resolve_addr(shared, source));
    if (likely(transaction->is_ro)){
        // read directly
        byte_wise_atomic_memcpy(target,
            resolve_addr(shared, source), 
            size, memory_order_acquire);
        v_lock_val = atomic_load(&region->segment_locks[segment_idx]);
    } else {
        insert_read(&(transaction->reads),segment_idx);

        uint old_lock_v = atomic_load(&region->segment_locks[segment_idx]); // prior lock load

        // check if read overlaps with write set
        // perform the corresponding read operations
        // calc start&end address
        unsigned char* start_adr = (unsigned char *)source;
        unsigned char* end_adr = (unsigned char *)source + (size -1);
        unsigned char* private_start_adr = (unsigned char *)target;
        while(size != 0){
            // loop through writes until we find a writes ending after our start address
            struct write_node* curr = transaction->writes;
            // OPTIMIZATION: skip based on segment id
            while (curr && (unsigned char *)curr->target + (curr->size -1) < start_adr){
                curr = curr->next;
            }
            // make sure that the write is not beyond our read
            if (curr && (unsigned char *)curr->target <= end_adr){
                unsigned char* ovr_start_adr = (unsigned char *)curr->target;
                unsigned char* ovr_end_adr = ovr_start_adr + curr->size;
                // copy from shared region if the overlap starts after our source
                if ( start_adr < ovr_start_adr){
                    size_t delta = ovr_start_adr - start_adr; // TODO:double check
                    byte_wise_atomic_memcpy((void *)private_start_adr,
                        resolve_addr(shared, (void *)start_adr), 
                        delta, memory_order_acquire);
                    start_adr += delta;
                    private_start_adr += delta;
                    size -= delta;
                }
                // now overwritten_start <= start_adr
                size_t ovr_offset = ovr_start_adr < start_adr ? start_adr - ovr_start_adr : 0;
                // copy from write buffer
                void * buffer_start = (void *)((unsigned char *)curr->source + ovr_offset);

                size_t delta = end_adr > ovr_end_adr ? (size_t)(ovr_end_adr - start_adr + 1): size;
                byte_wise_atomic_memcpy((void *)private_start_adr,
                    resolve_addr(shared, buffer_start), 
                    delta, memory_order_acquire);
                start_adr += delta;
                private_start_adr += delta;
                size -= delta;
            } else {
                // read directly
                #if DEBUG
                //if (!(transaction->is_ro)) printf("rw Direct single read spec. attempt, segment id %d %p. \n", segment_idx, target);
                //if ((transaction->is_ro)) printf("ro Direct single read spec. attempt. \n");
                #endif
                byte_wise_atomic_memcpy(target,
                    resolve_addr(shared, source), 
                    size, memory_order_acquire);
                #if DEBUG
                //if (!(transaction->is_ro)) printf("Done\n");
                #endif
                size = 0;
            }
        }
        
        v_lock_val = atomic_load(&(region->segment_locks[segment_idx])); // posterior lock load
        if(old_lock_v != v_lock_val){
            tx_clear(shared, tx, true);
            return false;
        }
    }
    // post-validation
    //   check that the lock is free
    //   and that the version of the lock is <= rv
    if ((v_lock_val & 1) || ((v_lock_val >> 1) > transaction->rv)){
        // post-validation failed
        tx_clear(shared, tx, true);
        return false;
    }
    return true;

    // TODO: add optimization for rw by checking if is a segment allocated in the current transaction
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t unused(shared), tx_t tx, void const* source, size_t size, void* target) {
    tx_con* transaction = (tx_con*)tx;
    insert_write(&(transaction->writes), source, size, target);
    
    // TODO: OPTIONAL first check, if this is a segment allocated in  the current transaction
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) {
    mem_region* region = (mem_region *)shared;

    // Allocate segment
    // 1. get the alignment from the pointer to the region
    size_t align = ((mem_region*) shared)->align;
    align = align < sizeof(struct segment_node*) ? sizeof(void*) : align;

    // sn is a pointer to a segment_node
    // we cast that into a pointer to a memory word (void**)
    void* segment;
    if (unlikely(posix_memalign(&segment, align, size) != 0)) return nomem_alloc; // Failed allocation!

    // store our address in the huge array of all addresses
    uint16_t segment_idx = get_seg_index(shared);
    ((struct region*)shared)->segment_addresses[segment_idx] = segment;
    // initialize the lock
    atomic_store(&(region->segment_locks[segment_idx]), 0);
    // TODO: book-keep that we have not yet commited this allocation

    // 0 everything and set target
    memset(segment, 0, size);
    *target = (void *)(((uint64_t) segment_idx) << 48);
    #if DEBUG
    printf(" Other than first segment allocated! %p \n", segment);
    #endif
    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: add this to a list of segments that will be freed upon commit
    return true;
}
