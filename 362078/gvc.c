#include "gvc.h"
#include "shared-lock.h"

#include "macros.h"

bool gvc_init(gvc* clock){
    clock->time = 0;
    return shared_lock_init(&(clock->lock));
}

bool gvc_increment(gvc* clock){
    if(unlikely(!shared_lock_acquire(&(clock->lock))))
        return false;
    
    clock->time++;
    shared_lock_release(&(clock->lock));
    return true;
}

bool gvc_read(gvc* clock, unsigned int* time){
    if(unlikely(!shared_lock_acquire_shared(&(clock->lock))))
        return false;
    
    *time = clock->time;
    shared_lock_release_shared(&(clock->lock));
    return true;
}

void gvc_clean_up(gvc* clock){
    shared_lock_cleanup(&(clock->lock));
}