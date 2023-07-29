#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include "mp2_given.h"
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group_ID");
MODULE_DESCRIPTION("CS-423 MP2");

#define DEBUG 1
#define R 'R'
#define Y 'Y'
#define D 'D'
#define SLEEPING 1
#define READY 2
#define RUNNING 3
static struct proc_dir_entry *my_proc_dir,*my_proc_entry;
static spinlock_t my_lock;
// declear mp2_PCB
typedef struct mp2_task_struct {
        struct list_head mp2_PCBs;
        struct task_struct* linux_task; // linux PCB, defined in <linux/sched.h>
        struct timer_list wakeup_timer;
    	unsigned int pid; // index, in ms
    	unsigned int period; // in ms
    	unsigned int processing_time; // in ms
    	unsigned long deadline; // in jiffiez
	unsigned int state;
} mp2_task_struct;
static LIST_HEAD(mp2_head);
DEFINE_MUTEX(mp2_current_running_task_mutex);
struct kmem_cache *task_cache;
static struct mp2_task_struct *current_running_task = NULL;
static struct task_struct *dispatching_thread;

// read call back function which send application a list of pids
static ssize_t proc_read(struct file *file, char *buf, size_t size,  loff_t *loff)
{
	// printk(KERN_ALERT "THIS IS READ CALL BACK FUNCTION\n");
	char* tempt_buf;
	tempt_buf = (char*)kmalloc(size+1, GFP_KERNEL);
	mp2_task_struct *cursor;
	unsigned long ret = 0;
	spin_lock_irq(&my_lock);
	list_for_each_entry(cursor, &mp2_head, mp2_PCBs) {
		ret += sprintf(tempt_buf + ret, "%u %u %u\n", cursor->pid, cursor->period, cursor->processing_time);
	}
	spin_unlock_irq(&my_lock);
	tempt_buf[ret] = '\0';
	copy_to_user(buf, tempt_buf, ret);
	kfree(tempt_buf);
   	if (*loff > 0) {
		*loff += ret;
		return 0;
	} else {
		*loff += ret;
		return ret;
	}
}

// determine if the task should be in the sheduler by bound

int admission_control(unsigned int pt, unsigned int period) {
	mp2_task_struct *cursor;
	unsigned int new_sum, old_sum = 0;
	unsigned int fixed_multiplier = 10000;
	unsigned int fixed_bound = 6930;
	spin_lock_irq(&my_lock);
        list_for_each_entry(cursor, &mp2_head, mp2_PCBs) {
                old_sum += cursor->processing_time * fixed_multiplier / cursor->period;
        }
	// printk(KERN_ALERT "old_sum(should be 0 now):%u\n",old_sum);
        spin_unlock_irq(&my_lock);
	new_sum = old_sum + pt * fixed_multiplier / period;
	// printk(KERN_ALERT "new_sum(should be 2,500 now):%u\n",new_sum);
	// printk(KERN_ALERT "fixed_bound(should be 6,930 now):%u\n",fixed_bound);
	if (new_sum <= fixed_bound) {
		// printk(KERN_ALERT "pass ac\n");
		return 1;
	} else {
		// printk(KERN_ALERT "do not pass ac\n");
	       	return 0;
	}
}

// get the task whose period is minimum

struct mp2_task_struct *get_the_highest_priority(void) {
	struct mp2_task_struct *cursor;
	struct mp2_task_struct *highest_priority = NULL;
	spin_lock_irq(&my_lock);
	list_for_each_entry(cursor, &mp2_head, mp2_PCBs) {
		if (cursor->state == READY) {
			if (highest_priority == NULL) {
				highest_priority = cursor;
			} else {
				if (highest_priority->period > cursor->period) highest_priority = cursor;
			}
		}
	}
	spin_unlock_irq(&my_lock);
	return highest_priority;
}

// waking up the task and rise its priority

void waking_up(mp2_task_struct *task) {
	struct sched_attr attr;
	printk(KERN_ALERT "wake up:%u\n", task->pid);
	wake_up_process(task->linux_task);
	attr.sched_policy=SCHED_FIFO;
	attr.sched_priority=99;
	sched_setattr_nocheck(task->linux_task, &attr);
}

// preempt the task by lowing its priority

void preempting(mp2_task_struct *task) {
	struct sched_attr attr;
	// printk(KERN_ALERT "preempt:%u\n", task->pid);
	attr.sched_policy=SCHED_NORMAL;
	attr.sched_priority=0;
	sched_setattr_nocheck(task->linux_task, &attr);
}

// perform CTX switching

static int dispatching(void *data) {
	struct mp2_task_struct *new_temp_task;
	while (1) {
		// let the dispatching sleep
		// TASK_UNINTERRUPTIBLE
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		// if kthread_stop(), then return
		if (kthread_should_stop()) {
			return 0;
		}
		mutex_lock_interruptible(&mp2_current_running_task_mutex);
		// printk(KERN_ALERT "start dispatching\n");
		new_temp_task = get_the_highest_priority();
		if (new_temp_task == NULL) {
			// no task in ready list // only yield case
			if (current_running_task != NULL) {
				// preempty the currently running task
				// set its state to READY if its state is RUNNING // no
				preempting(current_running_task);
				current_running_task = NULL;
			}
		} else { // there is ready task
			if (current_running_task != NULL) { // handle two cases: timer case where new task has higher priority and yield case
				if (current_running_task->state == RUNNING && current_running_task->period > new_temp_task->period) {
					// timer case: new task has higher priority
					current_running_task->state = READY;
					preempting(current_running_task);
                                        new_temp_task->state = RUNNING;
                                        waking_up(new_temp_task);
                                        current_running_task = new_temp_task;
				} else if (current_running_task->state == SLEEPING || current_running_task->state == READY) {
					// yield case where yield before ddl || after ddl
					preempting(current_running_task);
					new_temp_task->state = RUNNING;
                                	waking_up(new_temp_task);
                                	current_running_task = new_temp_task;
				} // do not perform reemption in timer case where the current task still has the highest priority
			} else { // handle a timer case where new task's timer expires and no currently running task
				new_temp_task->state = RUNNING;
                                waking_up(new_temp_task);
                                current_running_task = new_temp_task;
			}
		}
		mutex_unlock(&mp2_current_running_task_mutex);
	}
}

// wakeup_timer callback
void timer_callback(struct timer_list *timer) {
	unsigned int curr_pid;
	struct mp2_task_struct *curr;
	// printk(KERN_ALERT "THIS IS A TIMER CALL BACK FUNCTION\n");
	curr = from_timer(curr, timer, wakeup_timer);
	curr_pid = curr->pid;
	// printk(KERN_ALERT "timer_pid is :%u\n",curr_pid);
	curr->state = READY;
	wake_up_process(dispatching_thread);
	// printk(KERN_ALERT "end timer\n");
}

// when application sends R message, check if the register parameters of the task pass the admission control then add the task to list.
// R,<pid>,<period>,<processing time>
void register_task(char *buf) {
	struct mp2_task_struct *new_task;
	// int test = 2;
        new_task =(struct mp2_task_struct *)kmem_cache_alloc(task_cache, GFP_KERNEL);
	timer_setup(&(new_task->wakeup_timer), timer_callback, 0);
    	sscanf(strsep(&buf, ","), "%u", &new_task->pid);
	// printk(KERN_ALERT "pid:%u\n", new_task->pid);
	new_task->linux_task = find_task_by_pid(new_task->pid);
    	sscanf(strsep(&buf, ","), "%u", &new_task->period);
	// printk(KERN_ALERT "period:%u\n", new_task->period);
    	sscanf(strsep(&buf, "\n"), "%u", &new_task->processing_time);
	// printk(KERN_ALERT "processing time:%u\n", new_task->processing_time);
    	new_task->deadline = 0;
	new_task->state = SLEEPING;
	// printk(KERN_ALERT "here1\n");
	if (!admission_control(new_task->processing_time, new_task->period)) {
		// printk(KERN_ALERT "should not see me now!\n");
		return;
	}
	// printk(KERN_ALERT "here2\n");
	spin_lock_irq(&my_lock);
   	list_add(&new_task->mp2_PCBs, &mp2_head);
   	spin_unlock_irq(&my_lock);
	// test = list_empty(&mp2_head);
	// if (test == 0) printk(KERN_ALERT "good\n");
	// else printk(KERN_ALERT "bad\n");
}

// when application sends D message, remove the task from the list and free all data structures allocated during registration.
// D,<pid>
void deregister_task(char *buf) {
    	unsigned int pid;
    	struct mp2_task_struct *deleted_task;
	struct mp2_task_struct *cursor;
	// int test = 2;
    	sscanf(buf, "%u", &pid);
	printk(KERN_ALERT "deregister:%u\n", pid);
    	// remove task from the list
    	spin_lock_irq(&my_lock);
	list_for_each_entry(cursor, &mp2_head, mp2_PCBs) {
        	if (cursor->pid == pid) {
            		deleted_task = cursor;
			break;
        	}
	}
	if (deleted_task == NULL) printk(KERN_ALERT "OMG, NULL POINTER\n");
    	list_del(&deleted_task->mp2_PCBs);
    	spin_unlock_irq(&my_lock);
	// if the deleted task is currently running task
	mutex_lock_interruptible(&mp2_current_running_task_mutex);
	if (deleted_task == current_running_task) {
		current_running_task = NULL;
		wake_up_process(dispatching_thread);
	}
	mutex_unlock(&mp2_current_running_task_mutex);
	// delete timer
	del_timer(&(deleted_task -> wakeup_timer));
    	// free cache
    	kmem_cache_free(task_cache, deleted_task);
	// test = list_empty(&mp2_head);
        // if (test == 0) printk(KERN_ALERT "at least one task now\n");
        // else printk(KERN_ALERT "no task now\n");

}

// when application sends Y message, determine if it misses the ddl, if it misses, change the state to READY, otherwise let the task fall sleep. 
// Then CTX switch.
// Y,<pid>
void yield_task(char *buf) {
	unsigned int pid;
	struct mp2_task_struct *yielded_task;
        struct mp2_task_struct *cursor;
	u64 old_ddl, current_ddl, yield_after_ddl = 0;
	sscanf(buf, "%u", &pid);
	// find yielded_task by pid
	spin_lock_irq(&my_lock);
        list_for_each_entry(cursor, &mp2_head, mp2_PCBs) {
                if (cursor->pid == pid) {
                        yielded_task = cursor;
                        break;
                }
        }
        spin_unlock_irq(&my_lock);
	old_ddl = yielded_task->deadline; // last deadline when the task was woken
	if (old_ddl == 0) current_ddl = jiffies + msecs_to_jiffies(yielded_task -> period); // first time
	else {
		current_ddl = old_ddl + msecs_to_jiffies(yielded_task -> period); // current deadline
		pr_info("current_ddl %llu, old_ddl %llu\n", current_ddl, old_ddl);
		if (current_ddl < jiffies) yield_after_ddl = 1;
	}
	if (yield_after_ddl) {
		printk(KERN_ALERT "ready:%u\n", yielded_task->pid);
		yielded_task -> deadline = current_ddl + msecs_to_jiffies(yielded_task -> period);
		yielded_task -> state = READY;
	} else {
		printk(KERN_ALERT "sleep:%u\n", yielded_task->pid);
		yielded_task -> deadline = current_ddl;
		mod_timer(&(yielded_task -> wakeup_timer), yielded_task -> deadline);
		yielded_task -> state = SLEEPING;
	}
	wake_up_process(dispatching_thread);
	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule();
}


// write call back function which have a switch to separate each type of message(R, Y, D)
static ssize_t proc_write(struct file *file, const char *buf, size_t size,  loff_t *loff)
{
	// printk(KERN_ALERT "THIS IS WRITE CALL BACK FUNCTION\n");
	char* tempt_buf;
	tempt_buf= (char*)kmalloc(size+1, GFP_KERNEL);
	copy_from_user(tempt_buf, buf, size);
	tempt_buf[size] = '\0';
	// printk(KERN_ALERT "temp_buf:%c\n", tempt_buf[0]);
	switch (tempt_buf[0]) {
		case R:
			printk(KERN_ALERT "R MESSAGE");
			register_task(tempt_buf + 3);
			break;
		case Y:
			printk(KERN_ALERT "Y MESSAGE");
			yield_task(tempt_buf + 3);
			break;
		case D:
			printk(KERN_ALERT "D MESSAGE");
			deregister_task(tempt_buf + 3);
			break;
		default:
			printk(KERN_ALERT "ERROR SENDING A MESSAGE");
	}
	kfree(tempt_buf);
	return size;
}

// proc_ops of write and read dynamically
static const struct proc_ops wr_ops={
    .proc_read = proc_read,                   // read callback function
    .proc_write = proc_write                  // write callback function
};

// mp2_init - Called when module is loaded
int __init mp2_init(void)
{
        #ifdef DEBUG
        printk(KERN_ALERT "MP2 MODULE LOADING\n");
        #endif
        // Insert your code here ...
	// printk(KERN_ALERT "HELLO, WORLD\n");
	// initial a directory entry within the proc filesystem
        my_proc_dir = proc_mkdir("mp2", NULL);
        if(!my_proc_dir)
	{
		printk(KERN_INFO "Error creating proc dir");
		return -ENOMEM;
	}

        // initial a file entry, readable and writable by anyone
	my_proc_entry = proc_create("status", 0666, my_proc_dir, &wr_ops);
	if(!my_proc_entry)
	{
		printk(KERN_INFO "Error creating proc entry");
		return -ENOMEM;
	}
	// initialize a spin_lock
   	spin_lock_init(&my_lock);
	// initialize a cache
	task_cache = kmem_cache_create("task_cache", sizeof(mp2_task_struct), 0, SLAB_PANIC, NULL);
	// initialize and run a kernel thread
	dispatching_thread = kthread_run(dispatching, NULL, "dispatching_thread");

        printk(KERN_ALERT "MP2 MODULE LOADED\n");
        return 0;
}

// mp2_exit - Called when module is unloaded
void __exit mp2_exit(void)
{
	struct mp2_task_struct *cursor, *temp;
        #ifdef DEBUG
        printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
        #endif
        // Insert your code here ...
	// printk(KERN_ALERT "GOODBYE, WORLD\n");
	remove_proc_entry("status", my_proc_dir);
   	// remove dir entry mp2
   	remove_proc_entry("mp2", NULL);
	// free lock
	mutex_destroy(&mp2_current_running_task_mutex);
	// strop the thread
        kthread_stop(dispatching_thread);
   	// free linked list
   	list_for_each_entry_safe(cursor, temp, &mp2_head, mp2_PCBs) {
      		list_del(&cursor->mp2_PCBs);
      		kmem_cache_free(task_cache, cursor);
	}
	// free the cache
        kmem_cache_destroy(task_cache);

        printk(KERN_ALERT "MP2 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);
