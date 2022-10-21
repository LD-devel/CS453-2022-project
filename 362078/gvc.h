#pragma once

#include "shared-lock.h"

/**
 * @brief A simple global version clock guarded by
 * a readers-writers lock
*/
typedef struct global_version_clock {
    unsigned int time;
    struct shared_lock_t lock;
}gvc;

/** Initialize global version clock.
 * @param clock global version clock to be initalized
 * @return whether the initialization was a success
*/
bool gvc_init(gvc* clock);

/**
 * @brief Increment the verion clock value
 * @param clock global version clock to be incremented
 * @return Whether the operation is a success
*/
bool gvc_increment(gvc* clock);

/** Read the global version clock
 * @param clock global version clock to be read
 * @return Whether the operation is a success
*/
bool gvc_read(gvc* clock, unsigned int* time);

void gvc_clean_up(gvc* clock);

/* possibly implement the memory lock here
    we store a (pointer to a) memory word in the segment struct
*/