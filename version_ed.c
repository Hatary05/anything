//list.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const __typeof__(((type *)0)->member) *__mptr = (ptr);  \
        (type *)((char *)__mptr - offsetof(type, member)); })

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
	struct list_head* next, * prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct list_head* new,
	struct list_head* prev,
	struct list_head* next) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head* new, struct list_head* head) {
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head* new, struct list_head* head) {
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head* prev, struct list_head* next) {
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head* entry) {
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline void list_del_init(struct list_head* entry) {
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline void list_move(struct list_head* list, struct list_head* head) {
	__list_del(list->prev, list->next);
	list_add(list, head);
}

static inline void list_move_tail(struct list_head* list,
	struct list_head* head) {
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

static inline int list_empty(const struct list_head* head) {
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
  for (pos = (head)->next; pos != (head);	\
       pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
        	pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, __typeof__(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, __typeof__(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, __typeof__(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, __typeof__(*pos), member),	\
		n = list_entry(pos->member.next, __typeof__(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, __typeof__(*n), member))

#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, __typeof__(*pos), member),	\
		n = list_entry(pos->member.prev, __typeof__(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.prev, __typeof__(*n), member))

#if 0    //DEBUG
#define debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define debug(fmt, args...)
#endif

#define rep(i, n) for(int i = 0; i < (n); i++)
#define CS_LATENCY 10
#define IDLE 100

typedef struct{
    unsigned char op, len;
} code_tuple;

typedef struct{
    int pid, arrival_time, code_len;
    code_tuple* codes; 
    int tuple_cnt, idx;
    struct list_head list;
} process;

LIST_HEAD(job_queue); LIST_HEAD(waiting_queue);

int pending_cnt = 0;
void input_job_queue(){
    while(1){
        process* p = malloc(sizeof(process));
        if(fread(&p->pid, sizeof(int), 1, stdin) != 1) {free(p); return;}
        if(fread(&p->arrival_time, sizeof(int), 1, stdin) != 1) {free(p); return;}
        if(fread(&p->code_len, sizeof(int), 1, stdin) != 1) {free(p); return;}

        p->codes = malloc(p->code_len);
        if(fread(p->codes, 1, p->code_len, stdin) != p->code_len) {
            free(p->codes); free(p); return;
        }
        p->tuple_cnt = p->code_len / (sizeof(code_tuple)); p->idx = 0;

        INIT_LIST_HEAD(&p->list);

        int find = 0;
        struct list_head *pos;
        list_for_each(pos, &job_queue){
            process *tmp = list_entry(pos, process, list);
            if(p->arrival_time < tmp->arrival_time){
                list_add_tail(&p->list, pos);
                find = 1; break;
            }
            else if(p->arrival_time == tmp->arrival_time){
                if(p->pid < tmp->pid){
                    list_add_tail(&p->list, pos);
                    find = 1; break;
                }
            }
        }
        if(!find) list_add_tail(&p->list, &job_queue);
        pending_cnt++;
    }
}

typedef struct{
    int util;
    int cs, cs_time, work;
    int ready_q_cnt;
    struct list_head ready_q;
    process *cur; int prev_pid;
} CPU;
CPU cpu[2] = {
    {   
        .ready_q = LIST_HEAD_INIT(cpu[0].ready_q),
        .cur = NULL, .prev_pid = -1
    },
    {
        .ready_q = LIST_HEAD_INIT(cpu[1].ready_q),
        .cur = NULL, .prev_pid = -1
    }
};
int clock = 0;

void context_switching(){
    if(cpu[0].cs == 0 && cpu[1].cs == 0) return;
    rep(id, 2){
        if(cpu[id].cs_time > 0) cpu[id].cs_time--;
        if(cpu[id].cs && cpu[id].cs_time == 0){
            printf("%04d CPU%d: Switched\tfrom: %03d\tto: %03d\n",
                clock, id + 1, cpu[id].prev_pid, cpu[id].cur->pid
            );
            cpu[id].cs = 0;
        }
    }
}
void roading_cpu(){
    if(pending_cnt <= 0) return;

    process *p, *tmp;
    if(!list_empty(&waiting_queue)){
        list_for_each_entry_safe(p, tmp, &waiting_queue, list){
            if(cpu[0].cs && cpu[1].cs) break;
    
            int id = (cpu[0].ready_q_cnt <= cpu[1].ready_q_cnt ? 0 : 1);
            list_del(&p->list);
            list_add_tail(&p->list, &cpu[id].ready_q);
            cpu[id].ready_q_cnt++;
            printf("%04d CPU%d: Loaded PID: %03d\tArrival: %03d\tCodesize: %03d\n",
                clock, id + 1, p->pid, p->arrival_time, p->code_len
            );
            pending_cnt--;
        }
    }

    list_for_each_entry_safe(p, tmp, &job_queue, list){
        if(clock < p->arrival_time) break;
        if(cpu[0].cs && cpu[1].cs){
            int find = 0;
            struct list_head *pos;
            list_for_each(pos, &waiting_queue){
                process *tmp = list_entry(pos, process, list);
                if(p->pid <= tmp->pid){
                    list_move_tail(&p->list, pos);
                    find = 1; break;
                }
            }
            if(!find) list_move_tail(&p->list, &waiting_queue);
        }
        else{
            int id = (cpu[0].ready_q_cnt <= cpu[1].ready_q_cnt ? 0 : 1);
            list_del(&p->list);
            list_add_tail(&p->list, &cpu[id].ready_q);
            cpu[id].ready_q_cnt++;
            printf("%04d CPU%d: Loaded PID: %03d\tArrival: %03d\tCodesize: %03d\n",
                clock, id + 1, p->pid, p->arrival_time, p->code_len
            );
            pending_cnt--;
        }
    }
    if(clock == 0){
        for(int id = 0; id < 2; id++){
            process *p = malloc(sizeof(process));
            p->pid = IDLE, p->arrival_time = 0, p->code_len = sizeof(code_tuple);
            p->codes = NULL;
            INIT_LIST_HEAD(&p->list);
            list_add_tail(&p->list, &cpu[id].ready_q);
            cpu[id].ready_q_cnt++;
            printf("%04d CPU%d: Loaded PID: %03d\tArrival: %03d\tCodesize: %03d\n",
                clock, id + 1, p->pid, p->arrival_time, p->code_len
            );
        }
    }
}
void dispatch_cpu(){
    for(int id = 0; id < 2; id++){
        CPU *c = &cpu[id];
        if(c->cur != NULL && c->cur->pid != IDLE) continue;
        if(c->ready_q_cnt <= 0 || c->cs) continue;

        process *p = NULL;
        while(c->ready_q_cnt > 0){
            struct list_head *first = c->ready_q.next;
            process *front = list_entry(first, process, list);
            if(front->pid == IDLE && c->ready_q_cnt >= 2){
                list_move_tail(first, &c->ready_q);
                continue;
            }
            else {list_del(first); p = front; break;}
        }
        c->ready_q_cnt--;
        if(c->cur != NULL){
            c->prev_pid = c->cur->pid;
            list_add_tail(&c->cur->list, &c->ready_q);
            c->ready_q_cnt++;
        }
        if(c->prev_pid != -1){
            c->cs = 1; c->cs_time = CS_LATENCY;
        }
        c->cur = p;
    }
}
void working_cpu(){
    for(int id = 0; id < 2; id++){
        CPU *c = &cpu[id];
        if(c->cs) continue;

        process *p = c->cur;
        if(p == NULL) continue;
        if(p->pid == IDLE) {c->prev_pid = IDLE; continue;}

        if(c->work == 0 && p->codes[p->idx].op == 1){
            printf("%04d CPU%d: OP_IO START len: %03d ends at: %04d\n",
                clock, id + 1, p->codes[p->idx].len, clock + p->codes[p->idx].len
            );
        }
        if(p->codes[p->idx].op == 0) cpu[id].util++;
        if(++c->work == p->codes[p->idx].len){
            c->work = 0;
            if(p->tuple_cnt <= ++p->idx) {
                c->prev_pid = c->cur->pid;

                process *finished = p;
                c->cur = NULL;
                free(finished->codes);
                free(finished);
            }
        }
    }
}
int out(){
    if(cpu[0].cur == NULL || cpu[1].cur == NULL) return 0;
    if(pending_cnt > 0) return 0;

    int flag = 0;
    rep(id, 2){
        CPU *c = &cpu[id];
        if(c->cur->pid == IDLE && c->ready_q_cnt <= 0) flag++;
    }
    if(flag >= 2) return 1;
    return 0;
}
void simulation(){
    for(clock = 0; ;clock++){
        context_switching();
        roading_cpu();
        dispatch_cpu();
        working_cpu();
        if(out()) return;
    }
}
void show_statistics(){
    double util1 = 100 * cpu[0].util / (double)clock;
    double util2 = 100 * cpu[1].util / (double)clock;
    double tot_util = (util1 + util2) / 2;
    printf("*** TOTAL CLOCKS: %04d CPU1 IDLE: %04d CPU2 IDLE: %04d ",
        clock, clock - cpu[0].util, clock - cpu[1].util
    );
    printf("CPU1 UTIL: %2.2f%% CPU2 UTIL: %2.2f%% TOTAL UTIL: %2.2f%%\n",
        util1, util2, tot_util
    );
}
void free_memory(){
    process *p, *tmp;
    list_for_each_entry_safe(p, tmp, &job_queue, list) {
        list_del(&p->list);
        if (p->codes) free(p->codes);
        free(p);
    }
    list_for_each_entry_safe(p, tmp, &waiting_queue, list) {
        list_del(&p->list);
        if (p->codes) free(p->codes);
        free(p);
    }
    for (int id = 0; id < 2; id++) {
        list_for_each_entry_safe(p, tmp, &cpu[id].ready_q, list) {
            list_del(&p->list);
            if (p->codes) free(p->codes);
            free(p);
        }
        if (cpu[id].cur) {
            if (cpu[id].cur->codes) free(cpu[id].cur->codes);
            free(cpu[id].cur);
            cpu[id].cur = NULL;
        }
    }
}
int main(){
    input_job_queue();
    simulation();
    show_statistics();
    free_memory();
    return 0;
}
