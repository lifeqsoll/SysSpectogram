/* SPDX-License-Identifier: GPL-2.0-only
 *
 * sysspectogram_wd — optional hybrid protect helper (v0.9).
 *
 * Default OFF. Registers protected PIDs via sysfs and denies kill/ptrace from
 * non-allowlisted callers when the hook path is available.
 *
 * Honest limits: root can still rmmod / replace the module on many hosts;
 * cloud VPS often cannot load unsigned out-of-tree modules.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/pid.h>
#include <linux/sched.h>

#define SS_WD_MAX_PIDS 32
#define SS_WD_BUF 4096

static pid_t protected_pids[SS_WD_MAX_PIDS];
static int protected_count;
static DEFINE_SPINLOCK(ss_wd_lock);
static char admin_token[128] = "change-me";

module_param_string(admin_token, admin_token, sizeof(admin_token), 0600);
MODULE_PARM_DESC(admin_token, "token required to clear protected PIDs");

static ssize_t protected_pids_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	unsigned long flags;
	int i, n = 0;
	spin_lock_irqsave(&ss_wd_lock, flags);
	for (i = 0; i < protected_count; i++)
		n += scnprintf(buf + n, PAGE_SIZE - n, "%d\n", protected_pids[i]);
	spin_unlock_irqrestore(&ss_wd_lock, flags);
	return n;
}

static ssize_t protected_pids_store(struct kobject *kobj, struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	/* Format: "add <pid>" or "del <pid>" or "clear <token>" */
	char cmd[16];
	int pid = 0;
	char token[128];
	unsigned long flags;
	int i;

	if (sscanf(buf, "%15s %127s", cmd, token) < 1)
		return -EINVAL;

	if (strcmp(cmd, "clear") == 0) {
		if (strcmp(token, admin_token) != 0)
			return -EPERM;
		spin_lock_irqsave(&ss_wd_lock, flags);
		protected_count = 0;
		spin_unlock_irqrestore(&ss_wd_lock, flags);
		return count;
	}
	if (sscanf(buf, "%15s %d", cmd, &pid) != 2 || pid <= 1)
		return -EINVAL;

	spin_lock_irqsave(&ss_wd_lock, flags);
	if (strcmp(cmd, "add") == 0) {
		for (i = 0; i < protected_count; i++) {
			if (protected_pids[i] == pid)
				goto out;
		}
		if (protected_count >= SS_WD_MAX_PIDS) {
			spin_unlock_irqrestore(&ss_wd_lock, flags);
			return -ENOSPC;
		}
		protected_pids[protected_count++] = pid;
	} else if (strcmp(cmd, "del") == 0) {
		for (i = 0; i < protected_count; i++) {
			if (protected_pids[i] == pid) {
				protected_pids[i] = protected_pids[--protected_count];
				break;
			}
		}
	} else {
		spin_unlock_irqrestore(&ss_wd_lock, flags);
		return -EINVAL;
	}
out:
	spin_unlock_irqrestore(&ss_wd_lock, flags);
	return count;
}

static struct kobj_attribute protected_pids_attr =
	__ATTR(protected_pids, 0600, protected_pids_show, protected_pids_store);

static struct kobject *ss_wd_kobj;

static int __init ss_wd_init(void)
{
	int ret;
	ss_wd_kobj = kobject_create_and_add("sysspectogram_wd", kernel_kobj);
	if (!ss_wd_kobj)
		return -ENOMEM;
	ret = sysfs_create_file(ss_wd_kobj, &protected_pids_attr.attr);
	if (ret) {
		kobject_put(ss_wd_kobj);
		return ret;
	}
	pr_info("sysspectogram_wd: loaded (PID registry only; LSM deny hook is opt-in build)\n");
	return 0;
}

static void __exit ss_wd_exit(void)
{
	if (ss_wd_kobj) {
		sysfs_remove_file(ss_wd_kobj, &protected_pids_attr.attr);
		kobject_put(ss_wd_kobj);
	}
	pr_info("sysspectogram_wd: unloaded\n");
}

module_init(ss_wd_init);
module_exit(ss_wd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SysSpectogram");
MODULE_DESCRIPTION("Optional PID protect registry for SysSpectogram hybrid watchdog");
MODULE_VERSION("0.9.0");
