//  Note:
//  This code is based on Derek Molloy's excellent tutorial on creating Linux
//  Kernel Modules:
//    http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/signal.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/cred.h>

//  Define the module metadata.
#define MODULE_NAME "babel"
#define  DEVICE_NAME "babel"
#define  CLASS_NAME  "babel"
MODULE_AUTHOR("Dave Kerr");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A module which provides a device which talks gibberish");
MODULE_VERSION("0.1");

//  Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");
/* Additional module parameter: always signal this PID if >0 */
static int arg_pid = -1;
module_param(arg_pid, int, 0644);
MODULE_PARM_DESC(arg_pid, "PID to also signal on each write (-1 disables)");

//  The device number, automatically set. The message buffer and current message
//  size. The number of device opens and the device class struct pointers.
static int    majorNumber;
static char   message[256] = {0};
static short  messageSize;
static int    numberOpens = 0;
static struct class*  babelClass  = NULL;
static struct device* babelDevice = NULL;
static DEFINE_MUTEX(ioMutex);

/* ===== Signal payload support (demo) ===== */
struct babel_payload {
    u64 magic;
    pid_t target_pid;
    char preview[32];
};
static struct babel_payload *last_payload;

static int parse_leading_pid(const char *buf, size_t len, pid_t *out);
static int babel_send_signal(pid_t pid, const char *user_msg, size_t user_len);

//  Prototypes for our device functions.
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

//   Our main 'babel' function...
static char    babel(char input);

//  Create the file operations instance for our driver.
static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

static int __init mod_init(void)
{
    pr_info("%s: module loaded at 0x%p\n", MODULE_NAME, mod_init);

    //  Create a mutex to guard io operations.
    mutex_init(&ioMutex);

    //  Register the device, allocating a major number.
    majorNumber = register_chrdev(0 /* i.e. allocate a major number for me */, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        pr_alert("%s: failed to register a major number\n", MODULE_NAME);
        return majorNumber;
    }
    pr_info("%s: registered correctly with major number %d\n", MODULE_NAME, majorNumber);

    //  Create the device class.
    babelClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(babelClass)) {
        //  Cleanup resources and fail.
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_alert("%s: failed to register device class\n", MODULE_NAME);

        //  Get the error code from the pointer.
        return PTR_ERR(babelClass);
    }
    pr_info("%s: device class registered correctly\n", MODULE_NAME);

    //  Create the device.
    babelDevice = device_create(babelClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(babelDevice)) {
        class_destroy(babelClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_alert("%s: failed to create the device\n", DEVICE_NAME);
        return PTR_ERR(babelDevice);
    }
    pr_info("%s: device class created correctly\n", DEVICE_NAME);

    //  Success!
    return 0;
}

static void __exit mod_exit(void)
{
    pr_info("%s: unloading...\n", MODULE_NAME);
    device_destroy(babelClass, MKDEV(majorNumber, 0));
    class_unregister(babelClass);
    class_destroy(babelClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    mutex_destroy(&ioMutex);
    if (last_payload) { kfree(last_payload); last_payload = NULL; }
    pr_info("%s: device unregistered\n", MODULE_NAME);
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
    //  Try and lock the mutex.
    if(!mutex_trylock(&ioMutex)) {
        pr_alert("%s: device in use by another process", MODULE_NAME);
        return -EBUSY;
    }

    numberOpens++;
    pr_info("%s: device has been opened %d time(s)\n", MODULE_NAME, numberOpens);
    return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   int i = 0;
   char babelMessage[256] = { 0 };

   //   Create the babel content.
   for (; i<messageSize; i++) {
       babelMessage[i] = babel(message[i]);
   }

   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, babelMessage, messageSize);

   if (error_count==0) {
      pr_info("%s: sent %d characters to the user\n", MODULE_NAME, messageSize);
      //    Clear the position, return 0.
      messageSize = 0;
      return 0;
   }
   else {
      pr_err("%s: failed to send %d characters to the user\n", MODULE_NAME, error_count);
      //    Failed -- return a bad address message (i.e. -14)
      return -EFAULT;              
   }
}

/* Parse a leading decimal PID from buffer. */
static int parse_leading_pid(const char *buf, size_t len, pid_t *out)
{
    long v = 0; int any = 0; size_t i;
    for (i = 0; i < len; ++i) {
        char c = buf[i];
        if (c >= '0' && c <= '9') { any = 1; v = v*10 + (c-'0'); if (v > PID_MAX_LIMIT) return -ERANGE; }
        else break;
    }
    if (!any) return -EINVAL; *out = (pid_t)v; return 0;
}

/* Send SIGUSR1 with pointer payload (unsafe demo). */
static int babel_send_signal(pid_t pid, const char *user_msg, size_t user_len)
{
    struct pid *pid_struct; 
    struct task_struct *task; 
    struct kernel_siginfo info; 
    int ret;


    rcu_read_lock(); 
    pid_struct = find_get_pid(pid); 
    if(!pid_struct){ rcu_read_unlock(); pr_err("%s: no such pid %d\n", MODULE_NAME, pid); return -ESRCH; }

    task = get_pid_task(pid_struct, PIDTYPE_PID); 
    rcu_read_unlock(); 
    if(!task){ pr_err("%s: no task for pid %d\n", MODULE_NAME, pid); return -ESRCH; }

    if (last_payload) { kfree(last_payload); last_payload=NULL; }
    
    last_payload = kmalloc(sizeof(*last_payload), GFP_KERNEL); 
    if(!last_payload){ put_task_struct(task); return -ENOMEM; }

    get_random_bytes(&last_payload->magic, sizeof(last_payload->magic)); 
    last_payload->target_pid = pid;

    if (user_len > sizeof(last_payload->preview)-1) user_len = sizeof(last_payload->preview)-1; 
    memcpy(last_payload->preview, user_msg, user_len); 
    last_payload->preview[user_len]='\0';

    memset(&info,0,sizeof(info)); 
    info.si_signo = SIGUSR1; 
    info.si_code = SI_QUEUE; 
    info.si_pid = current->pid; 
    info.si_uid = from_kuid(&init_user_ns, current_uid()); 
    info.si_ptr = last_payload;
    ret = send_sig_info(SIGUSR1, &info, task);

    if(ret){ pr_err("%s: send_sig_info failed (%d) pid=%d\n", MODULE_NAME, ret, pid); kfree(last_payload); last_payload=NULL; }
    else { pr_info("%s: sent SIGUSR1 to %d payload=%p magic=%llx preview='%s'\n", MODULE_NAME, pid, last_payload, (unsigned long long)last_payload->magic, last_payload->preview); }
    
    put_task_struct(task);
    return ret;
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    size_t to_copy = len; long not_copied;


    if (to_copy >= sizeof(message)) to_copy = sizeof(message)-1;


    not_copied = copy_from_user(message, buffer, to_copy);
    messageSize = to_copy - (not_copied>0 ? not_copied:0); 
    message[messageSize]='\0';


    if (not_copied)
        pr_warn("%s: copy_from_user short (%ld bytes not copied)\n", MODULE_NAME, not_copied);
    else
        pr_info("%s: received %zu bytes: '%s'\n", MODULE_NAME, messageSize, message);
    
    if (arg_pid > 0 && arg_pid <= PID_MAX_LIMIT) {
        babel_send_signal(arg_pid, message, messageSize);
    }
    else {
        pr_info("%s: not sending signal (arg_pid=%d)\n", MODULE_NAME, arg_pid);
    }
    return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
     mutex_unlock(&ioMutex);
     pr_info("%s: device successfully closed\n", MODULE_NAME);
     return 0;
}

static char babel(char input) {
    if ((input >= 'a' && input <= 'm') || (input >= 'A' && input <= 'M')) {
       return input + 13;
    }
    if ((input >= 'n' && input <= 'z') || (input >= 'N' && input <= 'Z')) {
        return input - 13;
    }
    return input;
}


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

    

module_init(mod_init);
module_exit(mod_exit);

