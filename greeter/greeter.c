#include <linux/module.h>
#include <linux/init.h>

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/signal.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/random.h>



//  Define the module metadata.
#define MODULE_NAME "greeter"
MODULE_AUTHOR("Dave Kerr");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A simple kernel module to greet a user");
MODULE_VERSION("0.1");

//some example functions
int current_pid(void) {
	return current->pid;
}


//exposed kernel function
int kernel_add(int a, int b) {
	return a + b;
	pr_info("kernel_add: %d + %d = %d\n", a, b, a + b);
}
EXPORT_SYMBOL(kernel_add);



//signal test function



//  Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

/* Optional module parameter: decimal PID string to which we send a signal on load */
static char *signal_pid = NULL;
module_param(signal_pid, charp, 0644);
MODULE_PARM_DESC(signal_pid, "If set, send SIGUSR1 with a siginfo pointer payload to this PID at module init");

/* Sample heap data structure whose kernel pointer we (dangerously) leak via siginfo. */
struct greeter_payload {
    u64 magic;
    pid_t target_pid;
    char msg[32];
};
static struct greeter_payload *sent_payload;

/* WARNING: Passing a raw kernel pointer to userspace via si_ptr leaks a
 * kernel address (KASLR defeat) and userspace cannot legally dereference
 * it. This is for demonstration only. In production, pass an opaque
 * integer cookie instead and keep the pointer on the kernel side. */
static int greeter_send_signal_with_ptr()
{
    long pid_l;
    int ret;
    struct pid *pid_struct;
    struct task_struct *task;
    struct kernel_siginfo info; /* kernel_siginfo to avoid user copy */

    const char *pid_str = signal_pid;

    if (!pid_str || *pid_str == '\0') {
        pr_err("%s: signal pid string empty\n", MODULE_NAME);
        return -EINVAL;
    }
    ret = kstrtol(pid_str, 10, &pid_l);
    if (ret) {
        pr_err("%s: failed to parse pid '%s' (%d)\n", MODULE_NAME, pid_str, ret);
        return ret;
    }
    if (pid_l <= 0 || pid_l > PID_MAX_LIMIT) {
        pr_err("%s: pid out of range: %ld\n", MODULE_NAME, pid_l);
        return -ERANGE;
    }

    rcu_read_lock();
    pid_struct = find_get_pid((pid_t)pid_l);
    if (!pid_struct) {
        rcu_read_unlock();
        pr_err("%s: no such pid %ld\n", MODULE_NAME, pid_l);
        return -ESRCH;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    rcu_read_unlock();
    if (!task) {
        pr_err("%s: failed to get task for pid %ld\n", MODULE_NAME, pid_l);
        return -ESRCH;
    }

    sent_payload = kmalloc(sizeof(*sent_payload), GFP_KERNEL);
    if (!sent_payload) {
        put_task_struct(task);
        return -ENOMEM;
    }
    get_random_bytes(&sent_payload->magic, sizeof(sent_payload->magic));
    sent_payload->target_pid = (pid_t)pid_l;
    snprintf(sent_payload->msg, sizeof(sent_payload->msg), "hello-%llu", (unsigned long long)(sent_payload->magic & 0xffff));

    memset(&info, 0, sizeof(info));
    info.si_signo = SIGUSR1;
    info.si_code = SI_QUEUE; /* pretend queued signal */
    info.si_pid = current->pid;
    info.si_uid = from_kuid(&init_user_ns, current_uid());
    info.si_ptr = sent_payload; /* leaks kernel pointer! */

    ret = send_sig_info(SIGUSR1, &info, task);
    if (ret) {
        pr_err("%s: send_sig_info failed (%d) for pid %ld\n", MODULE_NAME, ret, pid_l);
        kfree(sent_payload);
        sent_payload = NULL;
    } else {
        pr_info("%s: sent SIGUSR1 to pid %ld with payload %p (magic=%llx msg=%s)\n",
                MODULE_NAME, pid_l, sent_payload,
                (unsigned long long)sent_payload->magic, sent_payload->msg);
    }
    put_task_struct(task);
    return ret;
}

static int __init greeter_init(void)
{
    pr_info("%s: module loaded at 0x%p\n", MODULE_NAME, greeter_init);
    pr_info("%s: greetings %s\n", MODULE_NAME, name);

    return 0;
}

static void __exit greeter_exit(void)
{
    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, greeter_exit);
    if (sent_payload) {
        /* Free the payload we allocated (userspace cannot free kernel memory). */
        kfree(sent_payload);
        sent_payload = NULL;
    }
}

module_init(greeter_init);
module_exit(greeter_exit);
