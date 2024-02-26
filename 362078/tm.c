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
#define DEBUG 0
#define DEBUG_DET 0
#define DEBUG_ADDR 0
#define DEBUG_LOCK 0

// External headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

// Internal headers
#include <tm.h>
#include "macros.h"
#include "lock.h"
#include "shared-lock.h"

typedef struct segment_index{
    //struct segment_index *prev;
    struct segment_index *next;
    uint16_t index;
    bool locked;
} seg_idx;

void append_idx(seg_idx** list, uint16_t idx){
    seg_idx* new_idx = malloc(sizeof(seg_idx));
    new_idx->index = idx;
    new_idx->next = NULL;

    new_idx->next = *list; //stack
    list = &new_idx;
}

/**
 * @brief Single linked list of writes
 */
struct write_node {
    struct write_node* prev;
    struct write_node* next;
    void* source;
    bool tbf;
    size_t size; // size of the relevant write, after potential overwrites
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
    seg_idx* allocations;
    size_t buffer_space;
    uint ctr;
    uint64_t buffer_w1;
    uint64_t buffer_w2;
} tx_con;

// Reads simply get inserted at the start of the list
void insert_read(read_list* reads_ptr, uint16_t segment_idx){
    #if DEBUG_DET
    printf("Insert read \n");
    #endif

    struct read_node* n_read = (struct read_node*) malloc(sizeof(struct read_node));
    n_read->next = *reads_ptr;
    n_read->prev = NULL;
    n_read->segment_idx = segment_idx;
    *reads_ptr = n_read;
}

// Write get inserted in a sorted manner and intervals get updated accordingly
void insert_write(write_list* writes_ptr, void const* source, size_t size, void* target, bool tbf){
    #if DEBUG_DET
    printf("insert_write\n");
    #endif

    struct write_node* n_write = (struct write_node*) malloc(sizeof(struct write_node));
    n_write->source = (void *)source;
    n_write->tbf = tbf;
    n_write->size = size;
    n_write->target = target;
    n_write->locked = false;
    n_write->prev = NULL;
    n_write->next = NULL;

    if(!(*writes_ptr)){ // In case the list is empty so far
        #if DEBUG_DET
        printf("insert_write 0-1 %p \n", writes_ptr);
        #endif
        (*writes_ptr) = n_write;
        return;
    }

    // find the correct slot to insert
    // we ensure that prev<new and next>=new
    #if DEBUG_DET
    printf("insert_write 1 \t %p \n", writes_ptr);
    #endif
    struct write_node* prev = NULL;
    struct write_node* next = *writes_ptr;
    #if DEBUG_DET
    printf("insert_write 1-1 %p \n", writes_ptr);
    #endif
    while (next && next->target < target){
        #if DEBUG_DET
        printf("insert_write 1-1.0 %p prev: %p next %p \n", writes_ptr, prev, next);
        #endif
        prev = next;
        #if DEBUG_DET
        printf("insert_write 1-1.1 %p prev: %p next %p \n", writes_ptr, prev, next);
        #endif
        next = next->next;
        #if DEBUG_DET
        printf("insert_write 1-1.2 %p prev: %p next %p \n", writes_ptr, prev, next);
        #endif
    }
    #if DEBUG_DET
    printf("insert_write 1-2 \t %p \n", writes_ptr);
    #endif
    if(prev) {
        prev->next = n_write;
    } else { // if there is no previous element, this is the first in the list
        (*writes_ptr) = n_write;
    }
    n_write->prev = prev;
    n_write->next = next;
    if(next) next->prev = n_write;

    #if DEBUG_DET
    printf("insert_write 2 \t %p \n", writes_ptr);
    #endif
    // update bounds of prev
    if(prev){
        uintptr_t prev_end = (uintptr_t)prev->target + (prev->size -1);
        uintptr_t new_start = (uintptr_t)n_write->target;
        if(prev_end >= new_start){
            prev->size = prev->size - (prev_end - new_start +1);
        }
    }
    // remove next if necessary
    uintptr_t new_end = (uintptr_t)n_write->target + (n_write->size -1);
    while(next && ((uintptr_t)next->target + (next->size -1)) <= new_end){
        n_write->next = next->next;
        free(next);
        next = n_write->next;
    }
    
    #if DEBUG_DET
    printf("insert_write 3 \t %p \n", writes_ptr);
    #endif
    // update next's target address and size if necessary
    if(next){
        uintptr_t next_start = (uintptr_t)next->target;
        if(next_start <= new_end){
            size_t delta = (new_end - next_start) + 1;
            next->target = (void*)(new_end + 1);
            next->size = next->size - delta;
            next->source = (void*)((uintptr_t)next->source + delta);
        }
    }
    #if DEBUG_DET
    printf("insert_write 4 \t %p \n", writes_ptr);
    #endif
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
    void* segment_addresses[65536]; // This should correspond to 2^16 entries
    atomic_uint segment_locks[65536];
    void* segment_locks_ptr[65536];
    seg_idx* available_idx;
} mem_region;

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
    void* real_base = ((mem_region *) shared)->segment_addresses[((uintptr_t) ptr >> 48)];
    uint64_t vv_base = (((uintptr_t) ptr) >> 48) << 48;
    uint64_t delta = ((uintptr_t) ptr) - vv_base;
    void* res = (void*)(((uintptr_t) real_base) + delta);
    #if DEBUG_ADDR
    printf("%p \t \t -> %p\n", ptr, res);
    #endif
    return res;
}

/**
 * @brief Determine and reserve the next free index in the array of memory segments
 * @param region Pointer to the region
 * @return Next free index in the array of memory segments
*/
uint16_t get_seg_index(shared_t shared){
    mem_region* region = (mem_region *)shared;
    uint16_t tmp_ctr;
    lock_acquire(&(region->segments_lock));
    if(!region->available_idx){
        tmp_ctr = region->ctr++;
    } else {
        tmp_ctr = region->available_idx->index;
        seg_idx* old = region->available_idx;
        region->available_idx = old->next;
        free(region->segment_addresses[old->index]);
        free(old);
    }
    // TODO: double check, if this is the correct fence
    //atomic_thread_fence(memory_order_acquire);
    lock_release(&(region->segments_lock));
    return tmp_ctr;
}

/**
 * @brief Hand back an index in the array of memory segments
 * due to either failure of a transaction or freeing of memory
 * @param shared Pointer to the region
 * @param index_old index to be freed
*/
void free_seg_index(shared_t shared, uint16_t index_old){
    mem_region* region = (mem_region *)shared;
    seg_idx* new_idx = malloc(sizeof(seg_idx));
    new_idx->index = index_old;
    new_idx->next = NULL;

    lock_acquire(&(region->segments_lock));
    new_idx->next = region->available_idx; //stack
    region->available_idx = new_idx;
    // corresponding memory must be freed before this call
    region->segment_addresses[index_old] = NULL;
    //atomic_thread_fence(memory_order_acquire);
    lock_release(&(region->segments_lock));
}

// tries to lock write node's segment, if locked
// returns whether successful
bool lock_node(mem_region* region, struct write_node* node){
    if(!node->locked){
        uint16_t segment_idx = (uint16_t)((uint64_t)node->target >> 48);
        uint v_lock_val = atomic_load(&(region->segment_locks[segment_idx]));
        if (!(v_lock_val & 1u)){
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
                #if DEBUG_LOCK
                printf("Unlocking (all) segment %d from %d to version %d \n", segment_idx, v_lock_val, (v_lock_val >> 1));
                #endif
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
void byte_wise_atomic_memcpy(void* dest, void* source, size_t count, memory_order order){
    memcpy(dest, source, count);
    /*for (size_t i = 0; i < count; ++i) {
        ((char*)(dest))[i] =
            atomic_load_explicit(((char*)(source))+i, order);
    }*/
    atomic_thread_fence(order);
}

/**
* Clean up after transaction
*/
void tx_clear(shared_t shared, tx_t tx, bool fail){
    #if DEBUG
    if (fail) printf("clearing failed transaction \n");
    #endif

    //mem_region* region = (mem_region *)shared;
    tx_con* transaction = (tx_con*)tx;

    if (unlikely(!transaction->is_ro)){    
        // if fail, free all allocs
        // if !fail, free all frees -> done in tm_end via write nodes
        // free the data structures in any case
        seg_idx* curr = transaction->allocations;
        while(curr){
            seg_idx* old = curr;
            curr = curr->next;
            if(fail) {
                //free(region->segment_addresses[old->index]);
                free_seg_index(shared, old->index);
            }
            //printf("free 1 %p \n", old);
            free(old);
        }
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
                // free the copy of the write buffer
                if(old->tbf)free(old->source);
                free(old);
            }
            if(curr->tbf)free(curr->source);
            free(curr);
        }
    }
    free(transaction);
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
    region->available_idx        = NULL;
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    mem_region* region = (mem_region*) shared;

    seg_idx* curr = region->available_idx;
    while(curr){
        region->segment_addresses[curr->index] = NULL;
        seg_idx* old = curr;
        curr = curr->next;
        free(old);
    }

    // free segments
    for (size_t i = 0; i < region->ctr; i++){
        // skip segments that have already been freed
        if (region->segment_addresses[i]) free(region->segment_addresses[i]);
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
    void* pointer = (void *)(((uintptr_t) 1u) << 48);
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

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) {
    #if DEBUG
    printf("tm_begin\n");
    #endif

    // TODO: Do we have to register the transaction with the region
    // for some reason? I don't see yet why we would.

    // Allocate memory for new transaction context.
    tx_con* tx_new = (tx_con*) malloc(sizeof(tx_con));
    if( unlikely(!tx_new)){
        #if DEBUG_DET
        printf("transaction allocation failed");
        #endif
        return invalid_tx;
    }
    mem_region* region = (mem_region *)shared;
    tx_new->rv = atomic_load(&(region->gvc)); // sample GVC
    tx_new->is_ro = is_ro;                    // store is_ro
    tx_new->reads = NULL;
    tx_new->writes = NULL;
    tx_new->allocations = NULL;
    tx_new->buffer_space = 0;
    tx_new->ctr = 0;
    tx_new->buffer_w1 = 0;
    tx_new->buffer_w2 = 0;
    return (tx_t) tx_new;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
    #if DEBUG
    printf("tm_end\n");
    #endif

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
                #if DEBUG_LOCK
                printf("locking %d\n", segment_idx);
                #endif
            }
            curr = curr->next;
            first = false;
        }
        // also lock free's TODO
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
    
    // TL2 step 5: validate the read set
    if(transaction->rv + 1 != wv){
        struct read_node* curr = transaction->reads;
        while (curr){
            uint16_t segment_idx = curr->segment_idx;
            uint v_lock_val = atomic_load(&(region->segment_locks[segment_idx]));
            bool valid = true;
            if ((v_lock_val >> 1) > transaction->rv) valid = false;
            // if segment is locked, check whether it is our own lock
            else if(v_lock_val & 1u) {
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
        uint16_t segment_idx_curr = (uint16_t)((uint64_t)curr->target >> 48);
        // write or free
        if(likely(curr->source)){   // write
            byte_wise_atomic_memcpy(resolve_addr(shared,curr->target), curr->source, curr->size, memory_order_acquire);
        } else {                    // free
            //free(resolve_addr(shared, curr->target));
            free_seg_index(shared, segment_idx_curr);
        }
        // if this write is the last of the segment, unlock
        if (!first && segment_idx != segment_idx_curr){
            // unlock last
            atomic_store(&(region->segment_locks[segment_idx]), wv<<1);
            #if DEBUG_LOCK
            if (segment_idx == 1){
                printf("Unlocking (after succ 1) segment %d to version %d \n", segment_idx, wv);
                printf("But value is %d \n", (atomic_load(&region->segment_locks[segment_idx]) >> 1));
            }
            #endif
        }
        if (!curr->next){
            // unlock current
            atomic_store(&(region->segment_locks[segment_idx_curr]), wv<<1);
            #if DEBUG_LOCK
            if (segment_idx_curr == 1){
                printf("Unlocking (after succ 2) segment %d to version %d \n", segment_idx_curr, wv);
                printf("But value is %d \n", (atomic_load(&region->segment_locks[segment_idx]) >> 1));
            }
            #endif
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
    #if DEBUG
    printf("tm_read\n");
    #endif
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)
    mem_region* region = (mem_region *)shared;
    tx_con* transaction = (tx_con *)tx;
    uint16_t segment_idx = (uint16_t)((uintptr_t) source >> 48);
    //printf("read segment: %d from ptr %p to buffer %p \n", segment_idx, source, target);
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
        uintptr_t start_adr = (uintptr_t)source;
        uintptr_t end_adr = (uintptr_t)source + (size -1);
        uintptr_t private_start_adr = (uintptr_t)target;
        while(size != 0){
            // loop through writes until we find a writes ending after our start address
            struct write_node* curr = transaction->writes;
            // OPTIMIZATION: skip based on segment id
            while (curr && (uintptr_t)curr->target + (curr->size -1) < start_adr){
                curr = curr->next;
            }
            // make sure that the write is not beyond our read
            if (curr && (uintptr_t)curr->target <= end_adr){
                uintptr_t ovr_start_adr = (uintptr_t)curr->target;
                uintptr_t ovr_end_adr = ovr_start_adr + curr->size;
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
                uintptr_t ovr_offset = ovr_start_adr < start_adr ? (start_adr - ovr_start_adr) : 0;
                // copy from write buffer
                void* buffer_start = (void *)((uintptr_t)curr->source + ovr_offset);

                size_t delta = end_adr > ovr_end_adr ? (size_t)(ovr_end_adr - start_adr + 1): size;
                //copy from own private buffer - no resolution or checking needed
                //printf("internal copy from ptr %p to %p \n",buffer_start ,(void *)private_start_adr);
                memcpy((void *)private_start_adr, buffer_start, delta);
                
                start_adr += delta;
                private_start_adr += delta;
                size -= delta;
            } else {
                // read directly
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
    if ((v_lock_val & 1u) || ((v_lock_val >> 1) > transaction->rv)){
        // post-validation failed
        #if DEBUG_LOCK
        printf("lock bit %d in segment %d \n", (v_lock_val & 1u), segment_idx);
        printf("lock version number %d rv %d \n", (v_lock_val >> 1), transaction->rv);
        printf("Current lock value is %d \n", (atomic_load(&region->segment_locks[segment_idx]) >> 1));
        #endif

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
    #if DEBUG
    printf("tm_write\n");
    #endif
    tx_con* transaction = (tx_con*)tx;
    transaction->buffer_space += size;
    
    //first copy the write buffer
    void* src_cpy;
    bool tbf = false;
    if (size == 8 && transaction->ctr == 0){
        src_cpy = &transaction->buffer_w1;
        transaction->ctr++;
    } else if (size == 8 && transaction->ctr == 1){
        src_cpy = &transaction->buffer_w2;
        transaction->ctr++;
    } else {
        src_cpy = malloc(size);
        tbf = true;
    }
    memcpy(src_cpy, source, size);
    
    insert_write(&(transaction->writes), src_cpy, size, target, tbf);
    
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
alloc_t tm_alloc(shared_t shared, tx_t tx, size_t size, void** target) {
    #if DEBUG
    printf("tm_alloc 0\n");
    #endif
    mem_region* region = (mem_region *)shared;

    // Allocate segment
    // 1. get the alignment from the pointer to the region
    size_t align = ((mem_region*) shared)->align;
    //align = align < sizeof(struct segment_node*) ? sizeof(void*) : align;

    // we cast that into a pointer to a memory word (void**)
    void* segment;
    if (unlikely(posix_memalign(&segment, align, size) != 0))
        return nomem_alloc; // Failed allocation!

    // store our address in the huge array of all addresses
    uint16_t segment_idx = get_seg_index(shared);
    ((struct region*)shared)->segment_addresses[segment_idx] = segment;
    // initialize the lock
    atomic_store(&(region->segment_locks[segment_idx]), 0);
    // list this, since it's not commited yet
    tx_con* transaction = (tx_con*)tx;
    append_idx(&(transaction->allocations), segment_idx);

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
bool tm_free(shared_t unused(shared), tx_t tx, void* target) {
    #if DEBUG
    printf("tm_free \n");
    #endif
    
    tx_con* transaction = (tx_con*)tx;
    insert_write(&(transaction->writes), NULL, (1ul << 48), target, false);

    return true;
}
