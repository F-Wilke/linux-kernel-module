#include <linux/module.h>
#include <linux/init.h>

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
// #include <linux/symbiote_hook.h>


//advanced version
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/pagemap.h>
#include <linux/pgtable.h>
#include <linux/slab.h>
// #include <linux/gup.h>

struct SymbiReg; /* your existing type */

typedef void (*symbi_hook_t)(struct pt_regs *regs,
                             const struct SymbiReg *sreg);

DEFINE_PER_CPU(unsigned long, srrar_start);
DEFINE_PER_CPU(unsigned long, bef_ker_ds);
DEFINE_PER_CPU(unsigned long, bef_rsp_set);

/* Register/unregister the single global hook */
int  symbi_register_hook(symbi_hook_t fn);
void symbi_unregister_hook(symbi_hook_t fn);


struct symbi_alias_ctx {
	void            *kva;         /* kernel VA base from vmap()     */
	unsigned long    user_base;   /* lowest user VA we aliased       */
	unsigned long    user_sp;     /* user RSP at setup time          */
	unsigned long    alias_sp;    /* kva + (user_sp - user_base)     */
	int              nr_pages;
	struct page    **pages;       /* pinned pages                    */
	bool             active;
};

struct SymbiReg {
  union {
    uint64_t raw;
    struct {
      uint64_t elevate     : 1; // Bit 0
      uint64_t query       : 1; // Bit 1
      uint64_t int_disable : 1; // Bit 2
      uint64_t debug       : 2; // Bit 3-4
      uint64_t no_smep     : 1; // Bit 5
      uint64_t no_smap     : 1; // Bit 6
      uint64_t toggle_smep : 1; // Bit 7
      uint64_t toggle_smap : 1; // Bit 8
      uint64_t ret         : 1; // Bit 9
      uint64_t fast_lower  : 1; // Bit 10
    };
  };
}__attribute__((packed));


#define SYMBI_ALIAS_PAGES_DEFAULT 8  /* map this many pages around RSP */

/* Simple runtime-controlled logging. 0=errors only, 1=info, 2=debug */
static int symbi_log_level = 1;
module_param(symbi_log_level, int, 0644);
MODULE_PARM_DESC(symbi_log_level, "0=errors only, 1=info, 2=debug");

#define SYMBI_LOG_ERR(fmt, ...) \
	pr_err("symbi: " fmt, ##__VA_ARGS__)
#define SYMBI_LOG_INFO(fmt, ...) \
	do { if (symbi_log_level >= 1) pr_info("symbi: " fmt, ##__VA_ARGS__); } while (0)
#define SYMBI_LOG_DBG(fmt, ...) \
	do { if (symbi_log_level >= 2) pr_info("symbi[dbg]: " fmt, ##__VA_ARGS__); } while (0)

static int symbi_alias_setup(struct pt_regs *regs,
			     struct symbi_alias_ctx **out_ctx,
			     int nr_pages)
{
	struct symbi_alias_ctx *ctx = NULL;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long rsp = regs->sp;                /* user RSP saved on entry */
	unsigned long first, last, cur;
	int i, got, ret = 0;

	SYMBI_LOG_INFO("alias_setup: task=%s[%d] regs=%p ip=%#lx sp=%#lx pages=%d\n",
				   current->comm, current->pid, regs, (unsigned long)regs->ip, rsp, nr_pages);

	if (nr_pages <= 0)
		nr_pages = SYMBI_ALIAS_PAGES_DEFAULT;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		SYMBI_LOG_ERR("alias_setup: kzalloc(ctx) failed\n");
		return -ENOMEM;
	}

	ctx->pages = kcalloc(nr_pages, sizeof(ctx->pages[0]), GFP_KERNEL);
	if (!ctx->pages) {
		ret = -ENOMEM;
		SYMBI_LOG_ERR("alias_setup: kcalloc(pages,%d) failed\n", nr_pages);
		goto err_free_ctx;
	}

	mmap_read_lock(mm);
	vma = find_vma(mm, rsp);
	if (!vma || vma->vm_start > rsp) {
		ret = -EFAULT;
		SYMBI_LOG_ERR("alias_setup: no VMA for RSP=%#lx (mm=%p)\n", rsp, mm);
		goto err_unlock;
	}
	/* Optional: insist it’s a grow-down stack VMA */
	/* if (!(vma->vm_flags & (VM_GROWSDOWN|VM_STACK))) ... */

	/* Pick a window of nr_pages ending at the page containing RSP.
	 * Clamp to the VMA so we don’t cross the guard page. */
	last  = ALIGN_DOWN(rsp, PAGE_SIZE);
	first = last - (nr_pages - 1UL) * PAGE_SIZE;
	if (first < vma->vm_start)
		first = vma->vm_start;
	ctx->user_base = first;
	ctx->user_sp   = rsp;

	SYMBI_LOG_DBG("alias_setup: VMA[%p] range=%#lx-%#lx flags=%#lx nr_pages(req)=%d\n",
				  vma, vma->vm_start, vma->vm_end, vma->vm_flags, nr_pages);
	SYMBI_LOG_INFO("alias_setup: window first=%#lx last=%#lx (len=%lu pages)\n",
				   first, last, ((last - first) / PAGE_SIZE + 1UL));

	/* Pin user pages so the alias is stable. Use FOLL_PIN on modern kernels. */
	got = pin_user_pages(first, (last - first) / PAGE_SIZE + 1,
	                     FOLL_WRITE | FOLL_LONGTERM, ctx->pages, NULL);
	if (got <= 0) {
		ret = got ? got : -EFAULT;
		SYMBI_LOG_ERR("alias_setup: pin_user_pages failed: ret=%d first=%#lx last=%#lx\n",
					  ret, first, last);
		goto err_unlock;
	}
	ctx->nr_pages = got;
	mmap_read_unlock(mm);

	SYMBI_LOG_INFO("alias_setup: pinned %d pages\n", got);
	for (i = 0, cur = first; i < got; i++, cur += PAGE_SIZE) {
		struct page *pg = ctx->pages[i];
		SYMBI_LOG_DBG("  page[%d]: user_va=%#lx page=%p pfn=%#lx\n",
					  i, cur, pg, (unsigned long)page_to_pfn(pg));
	}

	/* Create a contiguous kernel VA that aliases these pages */
	ctx->kva = vmap(ctx->pages, ctx->nr_pages, VM_MAP, PAGE_KERNEL);
	if (!ctx->kva) {
		ret = -ENOMEM;
		SYMBI_LOG_ERR("alias_setup: vmap failed for %d pages\n", ctx->nr_pages);
		goto err_unpin;
	}

	/* Compute alias_sp = kva + (rsp - user_base) */
	ctx->alias_sp = (unsigned long)ctx->kva + (ctx->user_sp - ctx->user_base);
	ctx->active   = true;

	SYMBI_LOG_INFO("alias_setup: kva=%p user_sp=%#lx user_base=%#lx alias_sp=%#lx\n",
				   ctx->kva, ctx->user_sp, ctx->user_base, ctx->alias_sp);
	SYMBI_LOG_DBG("alias_setup: ctx=%p active=%d nr_pages=%d mm=%p tgid=%d\n",
				  ctx, ctx->active, ctx->nr_pages, mm, current->tgid);

	/* (Optional) emulate a guard page at the low end by not mapping the very
	 * first page if you know vma->vm_start is a guard. For brevity, skipped. */

	*out_ctx = ctx;
	SYMBI_LOG_INFO("alias_setup: success (ctx=%p)\n", ctx);
	return 0;

err_unpin:
	/* Unpin any pages we did get */
	unpin_user_pages(ctx->pages, ctx->nr_pages);
	SYMBI_LOG_DBG("alias_setup: unpinned %d pages after failure\n", ctx->nr_pages);
	return ret;
err_unlock:
	mmap_read_unlock(mm);
	SYMBI_LOG_DBG("alias_setup: mmap_read_unlock after failure ret=%d\n", ret);
err_free_ctx:
	kfree(ctx);
	SYMBI_LOG_DBG("alias_setup: freed ctx after failure ret=%d\n", ret);
	return ret;
}


static void symbi_alias_teardown(struct symbi_alias_ctx **pctx)
{
	struct symbi_alias_ctx *ctx = pctx && *pctx ? *pctx : NULL;
	SYMBI_LOG_INFO("alias_teardown: ctx_ptr=%p ctx=%p\n", pctx, ctx);
	if (!ctx) {
		SYMBI_LOG_DBG("alias_teardown: nothing to do (NULL ctx)\n");
		return;
	}

	if (ctx->kva) {
		SYMBI_LOG_INFO("alias_teardown: vunmap kva=%p\n", ctx->kva);
		vunmap(ctx->kva);
	}
	if (ctx->pages && ctx->nr_pages > 0) {
		SYMBI_LOG_INFO("alias_teardown: unpin %d pages (pages=%p)\n", ctx->nr_pages, ctx->pages);
		unpin_user_pages(ctx->pages, ctx->nr_pages);
	}

	SYMBI_LOG_DBG("alias_teardown: free pages array=%p\n", ctx->pages);
	kfree(ctx->pages);
	SYMBI_LOG_INFO("alias_teardown: free ctx=%p and NULL out ptr\n", ctx);
	kfree(ctx);
	*pctx = NULL;
}


static void symbi_set_return_sp(struct pt_regs *regs, struct symbi_alias_ctx **pctx) {
	if (!regs || !pctx || !*pctx) {
		return;
	}
	struct symbi_alias_ctx *ctx = *pctx;

	
	unsigned long offset   = regs->sp - (unsigned long)ctx->kva;
	unsigned long user_sp  = ctx->user_base + offset;

	pr_info("calculating return stack address: curr sp: %#lx, curr offset from kva: %#lx, user base: %#lx, user sp: %#lx\n",
		 regs->sp, offset, ctx->user_base, user_sp);
	regs->sp = user_sp;

}


//end advanced version

struct symbi_alias_ctx* ctx = NULL; //for now: only one context, there wont be multiple elevated processes at a time

static void my_symbi_hook(struct pt_regs *regs, const struct SymbiReg *sreg)
{
	/* Runs in syscall/process context. Keep it lightweight.
	   Don’t sleep unless you know your syscall path allows it. */
	pr_info("symbi_hook: pid=%d rsp=%#lx flags=%#llx\n",
	         current->pid, regs->sp, sreg ? (unsigned long long)sreg->raw : 0ULL);
	/* You can inspect/modify regs here if you want to (but be careful!). */
    
    int ret;
	if (sreg->elevate) {
		pr_info("symbi_hook: starting elevate");
		ret = symbi_alias_setup(regs, &ctx, SYMBI_ALIAS_PAGES_DEFAULT);
		if (ret) {
			printk(KERN_ERR "symbi: alias_setup failed: %d\n", ret);
			/* You can choose to fail elevate here, or continue without alias */
			return;
		} 

		pr_info("setting context old rsp: %#lx to alias rsp: %#lx\n", regs->sp, ctx->alias_sp);
		regs->sp = ctx->alias_sp;

	}
	else {
		pr_info("symbi_hook: starting lower");
		symbi_set_return_sp(regs, &ctx);
		pr_info("symbi_hook: tearing down");
		symbi_alias_teardown(&ctx);
		pr_info("symbi_hook: teared down");
	}


}


//  Define the module metadata.
#define MODULE_NAME "stack_alias"
MODULE_AUTHOR("Fredrik Wilke");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A simple kernel that extends the kElevate mechanism to alias user stack pages into the kernel address space");
MODULE_VERSION("0.1");

//  Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

static int __init stack_alias_init(void)
{
    pr_info("%s: module loaded at 0x%p\n", MODULE_NAME, stack_alias_init);
    pr_info("%s: greetings %s\n", MODULE_NAME, name);

    int ret = symbi_register_hook(&my_symbi_hook);
	if (ret) {
		pr_err("symbi_probe: register failed: %d\n", ret);
		return ret;
	}
	pr_info("symbi_probe: hook registered\n");

	pr_info("srrar_start: %p\n", this_cpu_read(srrar_start));
	pr_info("bef_ker_ds: %p\n", this_cpu_read(bef_ker_ds));
	pr_info("bef_rsp_set: %p\n", this_cpu_read(bef_rsp_set));

    return 0;
}

static void __exit stack_alias_exit(void)
{
    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, stack_alias_exit);

    symbi_unregister_hook(&my_symbi_hook);
	pr_info("symbi_probe: hook unregistered\n");

	pr_info("srrar_start: %p\n", this_cpu_read(srrar_start));
	pr_info("bef_ker_ds: %p\n", this_cpu_read(bef_ker_ds));
	pr_info("bef_rsp_set: %p\n", this_cpu_read(bef_rsp_set));
}

module_init(stack_alias_init);
module_exit(stack_alias_exit);
