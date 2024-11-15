#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "cJSON.h"
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

#ifndef SCHED_IDLE
#define SCHED_NORMAL    0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
#define SCHED_IDLE		5
#endif

// These params references the source code of osnoise.
#define SAMPLE_PERIOD 1000000000 
#define NOISE_THRESHOLD 5000
#define SMALL_BUFLEN 32
#define MAXCPU 8

#define SHM_NAME "/my_shared_memory"  // /dev/shm/my_shared_memory
#define SHM_SIZE 524288  
#define THREAD_BLOCK_SIZE 4096 

#define HEADER_SIZE (sizeof(pthread_mutex_t) + sizeof(long) + sizeof(int))

typedef struct layout_header
{
    pthread_mutex_t mutex;
    long time;
    int len;
} layout_header;

typedef struct layout{
    layout_header header;
    unsigned char data[THREAD_BLOCK_SIZE - HEADER_SIZE]
} layout;

pthread_mutex_t *mutex;
pthread_mutexattr_t mutexAttr;

char *shm_ptr = 0;
layout* p_myself = 0; 



int first = 0;
volatile sig_atomic_t keep_running = 1;

long total_nsec_diff = 0;
long total_noise = 0;
long count = 0;
long max_time_span = 0;
int debug = 0;
int mock = 0;
int cpu = -1;
long this_diff = 0;
long interrupts = 0;

struct data_t {
    long count;
    long duration;
    long updatetime;
    long maxtime;
};

char *types[] = {"irq", "nmi", "softirq", "thread"};
char *map_paths[] = {
    "/sys/fs/bpf/irq_store",
    "/sys/fs/bpf/nmi_store",
    "/sys/fs/bpf/softirq_store",
    "/sys/fs/bpf/thread_store"
};
int map_fds[4] = {-1,-1,-1,-1}; 
struct data_t nmi, irq, softirq, thread; //lastvalue

void send_to_screen(cJSON* json) {
    const char *json_str = cJSON_PrintUnformatted(json);
    printf(json_str);
    free((void *)json_str);
}


cJSON* json_noise(long updatetime) {
    // Create JSON object
    cJSON *data_obj = cJSON_CreateObject();

    char str[SMALL_BUFLEN];
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", cpu);
    cJSON_AddStringToObject(data_obj, "cpu", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", count);
    cJSON_AddStringToObject(data_obj, "count", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", max_time_span);
    cJSON_AddStringToObject(data_obj, "maxsingle", str);
    long hw = 0;
    if(interrupts > count){
        hw = interrupts - hw;
    }
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", hw);
    cJSON_AddStringToObject(data_obj, "hardware", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", total_nsec_diff);
    cJSON_AddStringToObject(data_obj, "duration", str); 
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", total_noise);
    cJSON_AddStringToObject(data_obj, "noisetime", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", updatetime);
    cJSON_AddStringToObject(data_obj, "updatetime", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", SAMPLE_PERIOD);
    cJSON_AddStringToObject(data_obj, "period", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", NOISE_THRESHOLD);
    cJSON_AddStringToObject(data_obj, "threshold", str);

    cJSON_AddStringToObject(data_obj, "type", "sample");
    cJSON_AddStringToObject(data_obj, "command", "sql");
    cJSON_AddStringToObject(data_obj, "action", "nc-upload");

    return data_obj;
}

cJSON* json_tracer(int cpu, char* type, struct data_t *obj, long updatetime) {
    // Create JSON object
    // updatetime, use a simple way
    struct data_t* pcached = NULL;
    if(strcmp(type, "nmi")==0){
        pcached = &nmi;
    } else if(strcmp(type, "irq")==0){
        pcached = &irq;
    } else if(strcmp(type, "softirq")==0){
        pcached = &softirq;
    } else if(strcmp(type, "thread")==0){
        pcached = &thread;
    }

    cJSON *data_obj = cJSON_CreateObject();

    char str[SMALL_BUFLEN];
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", cpu);
    cJSON_AddStringToObject(data_obj, "cpu", str);
    memset(str, 0, SMALL_BUFLEN);
    if(pcached->maxtime = 0){
        sprintf(str, "%ld", obj->count);
        interrupts += obj->count;
    } else {
        long value = obj->count - pcached->count;
        if(value < 0){
            value = 0;
        }
        sprintf(str, "%ld", value);
        interrupts += value;
    }
    cJSON_AddStringToObject(data_obj, "count", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", obj->duration);
    cJSON_AddStringToObject(data_obj, "duration", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", obj->maxtime);
    cJSON_AddStringToObject(data_obj, "maxtime", str);
    memset(str, 0, SMALL_BUFLEN);
    sprintf(str, "%ld", updatetime);
    cJSON_AddStringToObject(data_obj, "updatetime", str);
    

    cJSON_AddStringToObject(data_obj, "type", type);
    cJSON_AddStringToObject(data_obj, "command", "sql");
    cJSON_AddStringToObject(data_obj, "action", "nc-upload");

    pcached->count = obj->count;
    pcached->duration = obj->duration;
    pcached->updatetime = obj->updatetime;
    pcached->maxtime = obj->maxtime;

    return data_obj;
}

void send_to_mockserver(cJSON* json){
    int sockfd;
    struct sockaddr_un addr;
    char *socket_path = "/tmp/unix_socket_mockbmcserver";

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("connect");
        close(sockfd);
        return;
    }

    if(json == 0){
        perror("send to mock server, error json\n");
        return;
    }
    
    const char *json_str = cJSON_PrintUnformatted(json);
    // Send JSON data
    if (write(sockfd, json_str, strlen(json_str)) == -1) {
        perror("write");
    }

    free((void *)json_str);
    close(sockfd);
}

void send_to_bmc(cJSON* json, long updatetime) {
    cJSON* uici = cJSON_GetObjectItem(json, "uici");
    const char *json_str = cJSON_PrintUnformatted(uici);
    int len = strlen(json_str);
    pthread_mutex_lock(&p_myself->header.mutex);
    p_myself -> header.time = updatetime;
    p_myself ->header.len = len;
    memcpy(p_myself->data, json_str, len * sizeof(char));
    p_myself->data[len] = 0;
    pthread_mutex_unlock(&p_myself->header.mutex);
    free((void *)json_str);
}

void process_map(int map_fd, int cpu, char *type, long nanoseconds, cJSON *jsonarray) {

    struct data_t values[MAXCPU];

    
    if (bpf_map_lookup_elem(map_fd, &cpu, values) == 0) {
       
        struct data_t *value = &values[cpu];
        
        cJSON_AddItemToArray(jsonarray, json_tracer(cpu, type, value, nanoseconds));
    } else {
        printf("mapfd: %d\n", map_fd);
        
        perror(type);
    }
}

void handle_noise_event(long nanoseconds, int cpu, cJSON *jsonarray) {
    
    for (int i = 0; i < 4; i++) {
        if(map_fds[i] < 0){
            map_fds[i] = bpf_obj_get(map_paths[i]);
        }
        if (map_fds[i] < 0) {
            perror(map_paths[i]);
            continue;
        }
        
        
        process_map(map_fds[i], cpu, types[i], nanoseconds, jsonarray);
    }
}

long timediff(struct timespec* ts, struct timespec* prev_ts){
    long sec_diff = ts->tv_sec - prev_ts->tv_sec;
    long nsec_diff = ts->tv_nsec - prev_ts->tv_nsec;
    if (nsec_diff < 0) {
        sec_diff -= 1;
        nsec_diff += 1000000000L;
    }
    return sec_diff * 1000000000L + nsec_diff;
}


void print_current_time_and_cpu(struct timespec *prev_ts) {
    struct timespec ts;
    struct timespec start;

    total_nsec_diff = 0;
    total_noise = 0;
    count = 0;
    max_time_span = 0;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) == -1) {
        perror("clock_gettime");
        return;
    }
    ts = start;
    *prev_ts = start;

    do {
        
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == -1) {
            perror("clock_gettime");
            return;
        }

        long sec_diff = ts.tv_sec - prev_ts->tv_sec;
        long nsec_diff = ts.tv_nsec - prev_ts->tv_nsec;
        if (nsec_diff < 0) {
            sec_diff -= 1;
            nsec_diff += 1000000000L;
        }
        this_diff = timediff(&ts, prev_ts);
        total_nsec_diff = timediff(&ts, &start);

        *prev_ts = ts;

        if (this_diff > NOISE_THRESHOLD) {
            count++;
            total_noise += this_diff;
            if (this_diff > max_time_span) {
                max_time_span = this_diff;
            }
        }

    } while (total_nsec_diff < SAMPLE_PERIOD);
    

    if (first == 1 && count > 0) {
        long nanoseconds = ts.tv_sec * 1000000000LL + ts.tv_nsec; 

        cJSON* json_obj = cJSON_CreateObject();
        cJSON* jsonarray = cJSON_CreateArray();
        printf("catch noise: %d\n", cpu);
        cJSON_AddItemToObject(json_obj, "uici", jsonarray);
        
        handle_noise_event(nanoseconds, cpu, jsonarray);
       
        cJSON_AddItemToArray(jsonarray, json_noise(nanoseconds));

        
        if (debug) {
            send_to_screen(json_obj);
        }
        if (mock) {
            send_to_mockserver(json_obj);
        } else {
            send_to_bmc(json_obj, nanoseconds);
        }
        
        interrupts = 0;
        
        cJSON_Delete(json_obj);


    } else if (first == 0) {
        first = 1;
    }

}

void handle_signal(int sig) {
    keep_running = 0;
}

int main(int argc, char **argv) {


    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
                debug = 1;
            }
            if (strcmp(argv[i], "--mock") == 0 || strcmp(argv[i], "-m") == 0) {
                mock = 1;
            }
        }
    }
    
    for (int i = 0; i < 4; i++) {
        if(map_fds[i] < 0){
            printf("try open %s\n", map_paths[i]);
            map_fds[i] = bpf_obj_get(map_paths[i]);
        }
        if (map_fds[i] < 0) {
            perror(map_paths[i]);
            continue;
        }
    }

    if(!mock){
        printf("try to open share memory...");
        
        int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666); 
        if (shm_fd == -1) {
            perror("shm_open");
            exit(1);
        }

        
        shm_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        
        if (shm_ptr == MAP_FAILED) {
            perror("mmap");
            close(shm_fd);
            exit(1);
        }
    }

    cpu = sched_getcpu();
    if (cpu == -1) {
        perror("sched_getcpu");
        return 1;
    }
    if(!mock){
        printf("success, cpu: %d\n", cpu);
        p_myself = (layout*)(shm_ptr + cpu * THREAD_BLOCK_SIZE);
        mutex = &p_myself->header.mutex;
        pthread_mutex_lock(&p_myself->header.mutex);
        p_myself -> header.time = 0;
        p_myself -> header.len = 0;
        memset(p_myself->data, 0, THREAD_BLOCK_SIZE - HEADER_SIZE);
        pthread_mutex_unlock(&p_myself->header.mutex);
    }
    
    struct sched_param param;
    param.sched_priority = 0;
    if (sched_setscheduler(0, SCHED_IDLE, &param) == -1) {
        fprintf(stderr, "Failed to set scheduler: %s\n", strerror(errno));
        return 1;
    }

    
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        
        if (pthread_mutex_unlock(mutex) != 0) {
            perror("pthread_mutex_unlock");
        }
        
        if (munmap(shm_ptr, SHM_SIZE) == -1) {
            perror("munmap");
        }
        return 1;
    }

    
    struct timespec prev_ts = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &prev_ts) == -1) {
        perror("clock_gettime");
        return 1;
    }

    while (keep_running) {
        print_current_time_and_cpu(&prev_ts);
    }
    
    if (munmap(shm_ptr, SHM_SIZE) == -1) {
        perror("munmap");
    }

    return 0;
}
