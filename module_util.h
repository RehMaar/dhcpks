#pragma once

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include <linux/slab.h>

#define PRINTINFO(_fmt, _args...) printk(KERN_INFO"dhcpks: " _fmt, ## _args)
#define PRINTALERT(_fmt, _args...) printk(KERN_ALERT"dhcpks: " _fmt, ## _args)

#define KALLOCATE(type, size) (type*)kmalloc(sizeof(type)*(size), GFP_KERNEL)

#define ARR_TO_NUM( arr, off )                                                \
   (arr[off] << 24)|(arr[1+off]<<16)|(arr[2+off]<<8)|(arr[3+off])  

#define DEBUG
