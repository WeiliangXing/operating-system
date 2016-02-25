#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xd46248e6, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xc8af564b, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xd2a941d4, __VMLINUX_SYMBOL_STR(sg_init_table) },
	{ 0x107e5878, __VMLINUX_SYMBOL_STR(zlib_inflateEnd) },
	{ 0xea011e5, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0xea01a685, __VMLINUX_SYMBOL_STR(mem_map) },
	{ 0x55925520, __VMLINUX_SYMBOL_STR(crypto_alloc_shash) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xda04f2f0, __VMLINUX_SYMBOL_STR(dget_parent) },
	{ 0x5fda0227, __VMLINUX_SYMBOL_STR(vfs_stat) },
	{ 0x56cb2648, __VMLINUX_SYMBOL_STR(sysptr) },
	{ 0x976cdd4f, __VMLINUX_SYMBOL_STR(dput) },
	{ 0x6118f29, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x62b72b0d, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xc499ae1e, __VMLINUX_SYMBOL_STR(kstrdup) },
	{ 0x466e7db2, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x343a1a8, __VMLINUX_SYMBOL_STR(__list_add) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xe24dd08a, __VMLINUX_SYMBOL_STR(unlock_rename) },
	{ 0xc671e369, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0x9e91457f, __VMLINUX_SYMBOL_STR(vfs_read) },
	{ 0x2bc95bd4, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x698bf581, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xdc798d37, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x5e3b3ab4, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xb31b06e, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x5152e605, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xaccda3a4, __VMLINUX_SYMBOL_STR(crypto_shash_digest) },
	{ 0xb6ed1e53, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0xce5ac24f, __VMLINUX_SYMBOL_STR(zlib_inflate_workspacesize) },
	{ 0x2b546102, __VMLINUX_SYMBOL_STR(lock_rename) },
	{ 0xe16b893b, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x521445b, __VMLINUX_SYMBOL_STR(list_del) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0xee236633, __VMLINUX_SYMBOL_STR(dentry_path_raw) },
	{ 0xf0f1246c, __VMLINUX_SYMBOL_STR(kvasprintf) },
	{ 0x5a0b73d0, __VMLINUX_SYMBOL_STR(zlib_deflateInit2) },
	{ 0x39dff39c, __VMLINUX_SYMBOL_STR(fput) },
	{ 0x581f98da, __VMLINUX_SYMBOL_STR(zlib_inflate) },
	{ 0xc2acc033, __VMLINUX_SYMBOL_STR(hex_dump_to_buffer) },
	{ 0xe9f7149c, __VMLINUX_SYMBOL_STR(zlib_deflate_workspacesize) },
	{ 0x4292364c, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0xf3bbde6a, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0x906c3b61, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0x979b36ce, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xb6c1d773, __VMLINUX_SYMBOL_STR(vfs_unlink) },
	{ 0x35a88f28, __VMLINUX_SYMBOL_STR(zlib_inflateInit2) },
	{ 0xf2c43f3f, __VMLINUX_SYMBOL_STR(zlib_deflate) },
	{ 0x7afa89fc, __VMLINUX_SYMBOL_STR(vsnprintf) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0x5c265cba, __VMLINUX_SYMBOL_STR(sg_init_one) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xe9aad35c, __VMLINUX_SYMBOL_STR(fget) },
	{ 0xc890c008, __VMLINUX_SYMBOL_STR(zlib_deflateEnd) },
	{ 0x6f55b81f, __VMLINUX_SYMBOL_STR(vfs_rename) },
	{ 0xd9665429, __VMLINUX_SYMBOL_STR(crypto_alloc_base) },
	{ 0xb5419b40, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xab2a4b93, __VMLINUX_SYMBOL_STR(do_pipe_flags) },
	{ 0x5966911e, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0x89b6a278, __VMLINUX_SYMBOL_STR(filp_open) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "53CD50F9457021790E3E2B9");
