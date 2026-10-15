#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>
#include <linux/msm_kgsl.h>

#define P(s) printf("%-42s size=%4zu %s\n", #s, sizeof(struct s), sizeof(struct s) > 128 ? "  <<< OVERFLOWS data[128]" : "")

int main(void)
{
    P(kgsl_command_object);
    P(kgsl_command_list);
    P(kgsl_gpu_command);
    P(kgsl_cmdlist_command);
    P(kgsl_create_passthrough);
    P(kgsl_context_create);
    P(kgsl_drawctxt_destroy);
    P(kgsl_device_getproperty);
    P(kgsl_sharedmem_find);
    P(kgsl_sharedmem_write);
    P(kgsl_sharedmem_read);
    P(kgsl_gpumem_alloc);
    P(kgsl_gpumem_alloc_id);
    P(kgsl_gpumem_free_id);
    P(kgsl_gpumem_sync_cache);
    P(kgsl_gpumem_sync_cache_bulk);
    P(kgsl_memdesc);
    P(kgsl_mem_entry);
    P(kgsl_timestamp_event);
    P(kgsl_dbg_buf_send_max);
    P(kgsl_dbglayer_create);
    P(kgsl_dbglayer_destroy);
    P(kgsl_dbglayer_query);
    P(kgsl_dbglayer_read);
    P(kgsl_dbglayer_get_max);
    P(kgsl_dbglayer_write);
    P(kgsl_dbglayer_send);
    P(kgsl_gpumem_sysmem_associate);
    P(kgsl_gpuobj_alloc);
    P(kgsl_gpuobj_free);
    P(kgsl_gpuobj_info);
    P(kgsl_gpuobj_import);
    P(kgsl_gpuobj_sync);
    P(kgsl_gpuobj_sync_obj);
    P(kgsl_gpuobj_set_info);
    P(kgsl_syncsource_create);
    P(kgsl_syncsource_destroy);
    P(kgsl_syncsource_create_fence);
    P(kgsl_syncsource_signal_fence);
    P(kgsl_cff_command);
    P(kgsl_cff_stream_config);
    P(kgsl_cff_stream_disable);
    P(kgsl_ioctl_preemption);
    P(kgsl_ioctl_supergroup);
    P(kgsl_ioctl_global_timestamp);
    P(kgsl_drawobj_create);
    P(kgsl_deviceless_command);
    P(kgsl_deviceless_getproperty);
    P(kgsl_deviceless_setproperty);
    P(kgsl_deviceless_alloc);
    P(kgsl_deviceless_free);
    /* the ioctl number size fields, decoded straight from the header */
#define SZ(c) do { unsigned long v = (unsigned long)(c); \
        printf("%-30s = %#lx  _IOC_SIZE=%lu%s\n", #c, v, (v >> 16) & 0x3fff, \
               (((v >> 16) & 0x3fff) > 128) ? "   <<< >128" : ""); } while (0)
    SZ(IOCTL_KGSL_GPUMEM_ALLOC_ID);
    SZ(IOCTL_KGSL_GPUOBJ_ALLOC);
    SZ(IOCTL_KGSL_GPUOBJ_SYNC);
    SZ(IOCTL_KGSL_GPU_COMMAND);
    SZ(IOCTL_KGSL_CMDLIST_IB);
    SZ(IOCTL_KGSL_CMDSTREAM_READTIMESTAMP);
    SZ(IOCTL_KGSL_CMDLIST_CREATE);
    SZ(IOCTL_KGSL_MEMSTORE);
    SZ(IOCTL_KGSL_DRAWCTXT_CREATE);
    SZ(IOCTL_KGSL_DEVICELESS_IOCTL);
    SZ(IOCTL_KGSL_TIMESTAMP_EVENT);
    SZ(IOCTL_KGSL_GPUMEM_SYNC_CACHE_BULK);
    SZ(IOCTL_KGSL_GPUOBJ_SET_INFO);
    SZ(IOCTL_KGSL_DBGLAYER_CREATE);
    SZ(IOCTL_KGSL_DBGLAYER_GET);
    SZ(IOCTL_KGSL_DBGLAYER_SEND);
    SZ(IOCTL_KGSL_DBGLAYER_READ);
    SZ(IOCTL_KGSL_DBGBUF_SEND);
    SZ(IOCTL_KGSL_CFF_STREAM_CONFIG);
    SZ(IOCTL_KGSL_CFF_DUMP_APP_MSG);
    SZ(IOCTL_KGSL_GETPROPERTY);
    return 0;
}
