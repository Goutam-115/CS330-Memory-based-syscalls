#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */
struct vm_area* create_node(u64 start, u64 end, int flag){ 
    struct vm_area* new = os_alloc(sizeof(struct vm_area));
    stats->num_vm_area++;
    new->access_flags = flag;
    new->vm_start = start;
    new->vm_end = end;
    new->vm_next = NULL;
    return new;
}

void merge(struct vm_area* head){
     struct vm_area* temp2 = head;
     struct vm_area* temp1 = head->vm_next;
     struct vm_area* tt = head->vm_next;

     while(temp1->vm_next!=NULL){
         if(temp1->vm_end == temp1->vm_next->vm_start && temp1->access_flags== temp1->vm_next->access_flags){
            temp2->vm_next = temp1;
            temp1->vm_end = temp1->vm_next->vm_end;
            struct vm_area* tempp = temp1->vm_next;
            temp1->vm_next=temp1->vm_next->vm_next;
            os_free(tempp, sizeof(struct vm_area));
            stats->num_vm_area--;
         }
         else{
            temp1 = temp1->vm_next;
            temp2 = temp2->vm_next;
         }
     }
}
//Function for merging vm_areas which are adjacent and same prot

int pfn_alloc(struct exec_context * current, u64 addr, int flags){
    u64 * ptaddr = (u64*)osmap(current->pgd);
    u64 offset;
    u64 p;
    for (int i = 0; i < 4; i++){
        offset = ((addr >> (39-(9*i))) & 0x1FF);
        if ((ptaddr[offset] & 1)==0){
            if(i<3){
                p = (u64)os_pfn_alloc(OS_PT_REG);
            }
            else{
                p = (u64)os_pfn_alloc(USER_REG);
            }
            ptaddr[offset] = (p << 12);
            ptaddr[offset] = ptaddr[offset] | 1 | 16;

            if(i<3){
                ptaddr[offset] = ptaddr[offset] | 8;
            }
            else if(flags & PROT_WRITE){
                ptaddr[offset]= ptaddr[offset] | 8;
            }
        }
        p = (ptaddr[offset] >> 12);
        ptaddr = (u64*) osmap(p);
    }
    return 1;
}

void pagetable_allocate(struct exec_context* parent, struct exec_context*new_ptable, u64 start, u64 end, int flags){
    for(u64 addr = start;addr<end;addr+=4096){
        int f=0;
        u64* old_ptaddr = osmap(parent->pgd);
        for(int i=0 ; i < 4; i++){
            u64 offset = (addr >> (39 - (9*i))) & (0x1FF);
            if((old_ptaddr[offset] & 1) == 0) break;

            if(i == 3){
                f = 1;
                break;
            }
            old_ptaddr = (u64*) osmap(old_ptaddr[offset] >> 12);
        }
        if (f!=0){
            u64* new_ptaddr = osmap(new_ptable->pgd);
            for(int i=0 ; i < 4; i++){
                u64 offset = (addr >> (39-(9*i))) & (0x1FF);
                if((new_ptaddr[offset] & 1)==0){
                    if(i == 3){
                        old_ptaddr[offset] = old_ptaddr[offset] & ~(0x8);
                        new_ptaddr[offset] = old_ptaddr[offset];
                        get_pfn( old_ptaddr[offset] >> 12);
                        break;
                    }
                    u32 pfn = os_pfn_alloc(OS_PT_REG);
                    new_ptaddr[offset] = pfn << 12;
                    new_ptaddr[offset] = new_ptaddr[offset] | 0x19;
                }
                new_ptaddr = osmap(new_ptaddr[offset]>>12);
            }
        }
    }
}

/**
 * mprotect System call Implementation.
 */
 int modify_mprotect(struct exec_context * current, u64 start, u64 end, int prot){

    for(u64 temp1 = start;temp1<end;temp1+=4096){
        u64 * ptaddr = (u64*)osmap(current->pgd);
        u64 offset;
        u64 p;
        for (int i = 0; i < 4; i++){
            offset = ((temp1 >> (39-(9*i))) & 0x1FF);
            if ((ptaddr[offset] & 1)==0){
                break;
            }
            p = (ptaddr[offset] >> 12);
            if (i == 3 && get_pfn_refcount(p) == 1){
                if (prot == PROT_READ){
                    ptaddr[offset] = ptaddr[offset] & ~(0x8);
                }else if (prot == PROT_READ|PROT_WRITE){
                    ptaddr[offset] = ptaddr[offset] | (0x8);
                }
                asm volatile ("invlpg (%0)" :: "r"(temp1): "memory");
            }
            else{
                ptaddr = (u64*) osmap(p);
            }
        }
    }
    return 0;

}
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (length < 0){
        return -EINVAL;
    }

    int padlen;
    padlen = ((length+4095)/4096)*4096;

    if (modify_mprotect(current, addr, addr + padlen, prot)){
        return -EINVAL;
    }

    
    struct vm_area * temp2 = current->vm_area;
    struct vm_area * temp1 = temp2->vm_next;
    while (temp1 != NULL){
        if ((addr + padlen <= temp1->vm_start )|| (addr >= temp1->vm_end)){ 
            if (addr + padlen <= temp1->vm_start){
                break;
            }
        }
        else if (addr <= temp1->vm_start && addr + padlen >= temp1->vm_end){
            temp1->access_flags = prot;
        }
        else if (addr > temp1->vm_start && addr + padlen< temp1->vm_end){
            if (prot != temp1->access_flags){
                struct vm_area * new1 = create_node(addr, addr+padlen, prot);
                struct vm_area * new2 = create_node(addr + padlen, temp1->vm_end, temp1->access_flags);
                new2->vm_next = temp1->vm_next;
                new1->vm_next = new2;
                temp1->vm_end = addr;
                temp1->vm_next = new1;
            }
        }
        else if(addr <= temp1->vm_start && addr + padlen < temp1->vm_end){
            if (prot != temp1->access_flags){
                struct vm_area * neww = create_node(temp1->vm_start, addr + length, prot);
                temp2->vm_next = neww;
                neww->vm_next = temp1;
                temp1->vm_start = addr + padlen;
            }
        }
        else if (addr > temp1->vm_start && addr + padlen >= temp1->vm_end){
            if (prot != temp1->access_flags){
                struct vm_area * neww = create_node(addr, temp1->vm_end, prot);
                neww->vm_next = temp1->vm_next;
                temp1->vm_next = neww;
                temp1->vm_end = addr;
            }
        }
        
        
        temp1 = temp1->vm_next;
        temp2 = temp2->vm_next;
    }

    merge(current->vm_area);
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{

    if(!(flags == 0 || flags == MAP_FIXED)){
        return -1;
    }

    if(!(prot == PROT_READ || (prot == (PROT_READ | PROT_WRITE)))){
        return -1;
    }

    if(addr != 0x0 && (addr < MMAP_AREA_START + 4096 || addr >= MMAP_AREA_END)){
        return -1;
    }

    if(length > 2*1024*1024 || length <= 0){
        return -1;
    }
    
    if (current->vm_area == NULL){ 
        struct vm_area* temp = create_node(MMAP_AREA_START,MMAP_AREA_START+4096, 0x0);
        current->vm_area = temp;
    }

    int padlen;
    padlen = ((length + 4095)/4096)*4096;

    if (addr == 0){
        
        if (flags == MAP_FIXED){
            return -EINVAL;
        }


        
        struct vm_area * temp1 = current->vm_area;
        struct vm_area * temp2 = temp1->vm_next;
        while (temp2 != NULL){
            if (temp2->vm_start >= temp1->vm_end+padlen ){
                break;
            }
            else{
            temp1 = temp2;
            temp2 = temp2->vm_next;
            }
        }

        if (temp1 == NULL && ( temp2->vm_end + length > MMAP_AREA_END)){
            return -EINVAL;
        }

        struct vm_area* tt = create_node(temp1->vm_end,temp1->vm_end+padlen,prot);

        temp1->vm_next = tt;
        tt->vm_next = temp2;

        merge(current->vm_area);

        return tt->vm_start;

    }
    else{
        struct vm_area * temp1 = current->vm_area->vm_next;
        int allocated = 0;
        while (temp1 != NULL){
            if (temp1->vm_start >= addr + padlen || temp1->vm_end <= addr){
                ;
            }
            else{
                allocated = 1;
                break;
            }
            temp1 = temp1->vm_next;
        }
        if (allocated && flags == MAP_FIXED){
            return -EINVAL;
        }
        else if (allocated == 1){

        struct vm_area * temp1 = current->vm_area;
        struct vm_area * temp2 = temp1->vm_next;
        while (temp2 != NULL){
            if (temp2->vm_start >= temp1->vm_end+padlen ){
                break;
            }
            else{
            temp1 = temp2;
            temp2 = temp2->vm_next;
            }
        }
        
        struct vm_area* tt = create_node(temp1->vm_end,temp1->vm_end+padlen,prot);

        temp1->vm_next = tt;
        tt->vm_next = temp2;

        merge(current->vm_area);

        return tt->vm_start;
        }
        else{
            temp1 = current->vm_area->vm_next;
            struct vm_area * temp2 = current->vm_area;
            while (temp1 != NULL){
                if (temp1->vm_start >= addr+length && temp2->vm_end <= addr){
                    break;
                }
                temp2 = temp1;
                temp1 = temp1->vm_next;
            }

            if (temp1 == NULL && MMAP_AREA_END < addr+padlen){
                return -EINVAL;
            }

            if (temp1 && temp1->vm_start == addr + length && temp1->access_flags == prot){ 
                if (temp2->vm_end == addr && temp2->access_flags == prot){ 
                    temp2->vm_end = temp1->vm_end;
                    temp2->vm_next = temp1->vm_next;
                    os_free(temp1, sizeof(struct vm_area));
                }else{
                    temp1->vm_start = addr;
                }
            }
            else if (temp2->vm_end == addr && temp2->access_flags == prot){ 
                temp2->vm_end += length;
            }
            else{
                temp2->vm_next = create_node(addr, length, prot);
                temp2->vm_next->vm_next = temp1;
            }
            return addr;
        }
    }
    return -EINVAL;
}

/**
 * munmap system call implemenations
 */
int modify_unmap(struct exec_context * current, u64 start, u64 end){

    for(u64 temp1 = start; temp1<end;temp1+=4096){
  
        u64 * ptaddr = (u64*)osmap(current->pgd);
        u64 offset;
        u64 p;
        for (int i = 0; i < 4; i++){
            offset = ((temp1 >> (39-(9*i))) & 0x1FF);
            if ((ptaddr[offset] & 1)==0){
                break;
            }
            p = (ptaddr[offset] >> 12);
            if (i == 3){
                ptaddr[offset] = 0;
                if (get_pfn_refcount(p) == 1){
                    put_pfn(p);
                    os_pfn_free(USER_REG, p);
                }
                else{
                    put_pfn(p);
                }
                asm volatile ("invlpg (%0)" :: "r"(temp1): "memory");
            }
            else{
                ptaddr = (u64*) osmap(p);
            }
        }
    }
    return 0;
}


long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if(length < 0){
        return -EINVAL;
    }

    if (length == 0){
        return 0;
    }

    
    struct vm_area * temp2 = current->vm_area;
    struct vm_area * temp1 = temp2->vm_next;

    int padlen;
    padlen = ((length+4095)/4096)*4096;

    if (modify_unmap(current, addr, addr + padlen)){
        return -EINVAL;
    }


    while (temp1 != NULL){
        if (temp1->vm_end <= addr || temp1->vm_start >= addr + padlen){
             temp2 = temp1;
             temp1 = temp1->vm_next;
        }
        else{
        if (temp1->vm_start >= addr && temp1->vm_end <= addr + padlen){
            temp2->vm_next = temp1->vm_next;
            os_free(temp1, sizeof(struct vm_area));
            stats->num_vm_area--;
            temp1 = temp2->vm_next;
            continue;
        }
        else if (temp1->vm_start < addr && temp1->vm_end > addr + padlen){
            struct vm_area* new = create_node(addr + length, temp1->vm_end, temp1->access_flags);
            new->vm_next = temp1->vm_next;
            temp1->vm_end = addr;
            temp1->vm_next = new;
        }
        else if (temp1->vm_start < addr && temp1->vm_end <= addr + padlen){
            temp1->vm_end = addr;
        }
        else if (temp1->vm_end > addr + padlen && temp1->vm_start >= addr){
            temp1->vm_start = addr+length;
        }

        temp2 = temp1;
        temp1 = temp1->vm_next;
        }
    }

    return 0;
}


/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area * temp1 = current->vm_area;
    while (temp1!=NULL){
        if (temp1->vm_start <= addr && temp1->vm_end > addr){

            if(error_code == 0x7 && (temp1->access_flags & PROT_WRITE)){
                return handle_cow_fault(current, addr, temp1->access_flags);
            }
            else if((error_code == 0x6 && (temp1->access_flags & PROT_WRITE)) || (error_code == 0x4 && (temp1->access_flags & PROT_READ))){
                return pfn_alloc(current, addr, temp1->access_flags);
            }
            else{
                return -1;
            }
        }
        temp1 = temp1->vm_next;
    }
    return -1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

long do_cfork(){
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
     /* Do not modify above lines
     * 
     * */   
     /*--------------------- Your code [start]---------------*/

    pid = new_ctx->pid;
    memcpy(new_ctx, ctx, sizeof(struct exec_context));
    new_ctx->pid=  pid;

    new_ctx->ppid = ctx->pid;
    
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);

    new_ctx->vm_area = NULL;

    struct  vm_area* new_vm = new_ctx->vm_area;
    struct  vm_area* parent_vm = ctx->vm_area;

    if(parent_vm!=NULL){
        new_vm = create_node(parent_vm->vm_start, parent_vm->vm_end, parent_vm->access_flags);
        stats->num_vm_area--;
        new_ctx->vm_area = new_vm;
        
        pagetable_allocate(ctx, new_ctx, parent_vm->vm_start, parent_vm->vm_end, parent_vm->access_flags);
        parent_vm = parent_vm->vm_next;
    }
    while(parent_vm!=NULL){
        struct vm_area* neww = create_node(parent_vm->vm_start, parent_vm->vm_end, parent_vm->access_flags);
        stats->num_vm_area--;
        pagetable_allocate(ctx, new_ctx,parent_vm->vm_start, parent_vm->vm_end, parent_vm->access_flags);
        new_vm->vm_next = neww;
        new_vm = neww;
        parent_vm = parent_vm->vm_next;
    }


    for(int i = MM_SEG_CODE; i < MAX_MM_SEGS ; i++){
        if(i == MM_SEG_STACK){
            pagetable_allocate(ctx, new_ctx,ctx->mms[i].start, ctx->mms[i].end, ctx->mms[i].access_flags);
        } 
        else{
            pagetable_allocate(ctx, new_ctx, ctx->mms[i].start, ctx->mms[i].next_free,ctx->mms[i].access_flags);
        } 
    }


     /*--------------------- Your code [end] ----------------*/
    
     /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}



/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64* ptaddr = osmap(current->pgd);

    for(int i=0; i < 4; i++){
        u64 offset = (vaddr >> (39 - (9*i))) & (0x1FF);

        if(( ptaddr[offset] & 1)==0){
            return -EINVAL;
        }
        

        u64 temp = ptaddr[offset] >> 12;
        if(i<3){
            ptaddr = osmap(temp);
        }

        else{
            if(get_pfn_refcount(temp) > 1){
                u32 pfn = os_pfn_alloc(USER_REG);
                u64* new_ptableaddr = (u64*)osmap(pfn);
                memcpy((void *)new_ptableaddr, osmap(temp), 4096);
                ptaddr[offset] = (pfn << 12) | 0x19;
                asm volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
            }
            else{
                ptaddr[offset] = ptaddr[offset] | 0x8;
                asm volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
            }
            ptaddr = osmap(temp);
        }
        
    }
 return 1;

}


